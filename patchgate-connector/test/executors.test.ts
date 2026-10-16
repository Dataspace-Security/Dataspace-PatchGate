import { generateKeyPairSync, createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { CacheDownloader } from "../src/cache/download.ts";
import { CacheIndex } from "../src/cache/cache-index.ts";
import { JobError } from "../src/jobs/errors.ts";
import { executeJob, type ExecutorDeps } from "../src/jobs/executors.ts";
import { createPatchGateClient } from "../src/pg-client.ts";
import { rawFromPublicKey, type JobPackage } from "../src/protocol.ts";
import { createTacticalClient } from "../src/tactical/client.ts";
import { silentLogger } from "../src/util/log.ts";
import { tempDir } from "./helpers/common.ts";
import { FakePatchGate } from "./helpers/fake-patchgate.ts";
import { FakeTactical, upd } from "./helpers/fake-tactical.ts";

const KEY = "TACTICAL-TEST-KEY-123";
const A1 = "agentAAAA1111";
const A2 = "agentBBBB2222";
const G = (n: number) => `${String(n).padStart(8, "0")}-0000-4000-8000-000000000000`;

let tactical: FakeTactical;
let pg: FakePatchGate;
let dir: string;
let cleanup: () => Promise<void>;
let deps: ExecutorDeps;
let index: CacheIndex;

beforeAll(async () => {
  pg = new FakePatchGate();
  await pg.start();
});
afterAll(async () => pg.stop());

beforeEach(async () => {
  ({ dir, cleanup } = await tempDir());
  tactical = new FakeTactical({ apiKey: KEY });
  await tactical.start();
  const conn = generateKeyPairSync("ed25519");
  pg.connectors.set("conn-test", { publicKey: rawFromPublicKey(conn.publicKey), tenantId: "t1" });
  const pgClient = createPatchGateClient({ serverUrl: pg.url, connectorId: "conn-test", privateKey: conn.privateKey, timeoutMs: 5000 });
  const root = join(dir, "cache");
  index = await CacheIndex.open(join(dir, "idx.json"), root);
  deps = {
    tactical: createTacticalClient({ baseUrl: tactical.url, apiKey: KEY, timeoutMs: 5000 }),
    index,
    downloader: new CacheDownloader({ pg: pgClient, index, root, maxPackageBytes: 1024 * 1024, minFreeBytes: 0, log: silentLogger }),
    cacheBaseUrl: "http://127.0.0.1:1/repo",
    installScriptId: 42,
    installScriptTimeoutSec: 60,
    maxParallelCalls: 4,
    log: silentLogger,
  };
});
afterEach(async () => {
  await tactical.stop();
  await cleanup();
});

const expectJobError = async (p: Promise<unknown>, retryable: boolean, msg: RegExp) => {
  const err = await p.then(
    () => null,
    (e: unknown) => e,
  );
  expect(err).toBeInstanceOf(JobError);
  expect((err as JobError).retryable).toBe(retryable);
  expect((err as JobError).message).toMatch(msg);
};

describe("SYNC_AGENTS / SCAN / COLLECT", () => {
  it("lists agents", async () => {
    tactical.addAgent({ agent_id: A1 });
    tactical.addAgent({ agent_id: A2, status: "offline" });
    tactical.addAgent({ agent_id: "bad id!" });
    const r = (await executeJob("SYNC_AGENTS", {}, deps)) as { agents: Array<{ agentId: string; online: boolean }> };
    expect(r.agents.map((a) => [a.agentId, a.online])).toEqual([
      [A1, true],
      [A2, false],
    ]);
  });

  it("passes Tactical last_seen / boot_time through (PatchGate normalises them); odd types never fail the list", async () => {
    tactical.addAgent({ agent_id: A1, last_seen: "2026-10-16T11:59:30.123456Z", boot_time: 1_760_601_600.25 });
    tactical.addAgent({ agent_id: A2, last_seen: 12345, boot_time: "1760601600" });
    tactical.addAgent({ agent_id: "agentCCCC3333", boot_time: { weird: true } });
    const r = (await executeJob("SYNC_AGENTS", {}, deps)) as { agents: Array<{ agentId: string; lastSeen: string | null; bootTime: number | null }> };
    expect(r.agents.map((a) => [a.agentId, a.lastSeen, a.bootTime])).toEqual([
      [A1, "2026-10-16T11:59:30.123456Z", 1_760_601_600.25],
      [A2, null, 1_760_601_600],
      ["agentCCCC3333", null, null],
    ]);
  });

  it("SCAN reports per-agent failures without failing the batch", async () => {
    tactical.addAgent({ agent_id: A1 });
    tactical.addAgent({ agent_id: A2, failStatus: 400 });
    const r = await executeJob("SCAN", { agentIds: [A1, A2] }, deps);
    expect(r).toMatchObject({ requested: [A1], failed: [{ agentId: A2, error: expect.stringContaining("400") }] });
  });

  it("COLLECT gathers updates, software and agent version; per-agent errors stay per-agent", async () => {
    tactical.addAgent({ agent_id: A1, updates: [upd(G(1))], software: [{ name: "7-Zip", version: "23.01", publisher: "Igor" }] });
    tactical.addAgent({ agent_id: A2, failStatus: 500 });
    const r = (await executeJob("COLLECT", { agentIds: [A1, A2], updates: true, software: true, agent: true }, deps)) as {
      agents: Array<Record<string, unknown>>;
    };
    expect(r.agents[0]).toMatchObject({ agentId: A1, updates: [{ guid: G(1) }], software: [{ name: "7-Zip" }], agent: { version: "2.10.0" } });
    expect(r.agents[1]).toMatchObject({ agentId: A2, error: expect.stringContaining("500") });
  });

  it("fails the batch (retryable) when Tactical itself is unreachable", async () => {
    tactical.addAgent({ agent_id: A1 });
    await tactical.stop();
    await expectJobError(executeJob("SCAN", { agentIds: [A1] }, deps), true, /unreachable/);
  });
});

describe("DEPLOY_WINDOWS", () => {
  it("approves exactly the requested GUIDs, resets everything else, verifies, then installs", async () => {
    const a = tactical.addAgent({
      agent_id: A1,
      updates: [upd(G(1)), upd(G(2), { action: "approve" }), upd(G(3), { action: "inherit" }), upd(G(4), { installed: true, action: "approve" })],
    });
    const r = await executeJob("DEPLOY_WINDOWS", { agentId: A1, guids: [G(1).toUpperCase()], rebootPolicy: "NEVER" }, deps);
    expect(r).toEqual({ outcome: "INSTALL_STARTED", approved: [G(1)] });
    expect(a.updates.map((u) => u.action)).toEqual(["approve", "nothing", "nothing", "approve"]);
    expect(tactical.installs).toEqual([A1]);
  });

  it("NOTHING_TO_DO when the updates are already installed or not offered (still clears stale approvals)", async () => {
    const a = tactical.addAgent({ agent_id: A1, updates: [upd(G(1), { installed: true }), upd(G(2), { action: "approve" })] });
    const r = await executeJob("DEPLOY_WINDOWS", { agentId: A1, guids: [G(1), G(9)], rebootPolicy: "IF_REQUIRED" }, deps);
    expect(r).toEqual({ outcome: "NOTHING_TO_DO", approved: [] });
    expect(a.updates[1]!.action).toBe("nothing");
    expect(tactical.installs).toEqual([]);
  });

  it("refuses to install when Tactical's policy keeps another update approved, and withdraws approvals", async () => {
    const a = tactical.addAgent({ agent_id: A1, updates: [upd(G(1)), upd(G(2), { action: "approve" })] });
    tactical.policyApproved.add(a.updates[1]!.id);
    await expectJobError(executeJob("DEPLOY_WINDOWS", { agentId: A1, guids: [G(1)], rebootPolicy: "NEVER" }, deps), false, /approval state mismatch/);
    expect(tactical.installs).toEqual([]);
    expect(a.updates[0]!.action).toBe("nothing"); // our approval withdrawn
  });

  it("agent offline is retryable", async () => {
    tactical.addAgent({ agent_id: A1, failStatus: 400 });
    await expectJobError(executeJob("DEPLOY_WINDOWS", { agentId: A1, guids: [G(1)], rebootPolicy: "NEVER" }, deps), true, /400/);
  });
});

describe("RESET_APPROVALS", () => {
  it("returns pending approvals to not-approved", async () => {
    const a = tactical.addAgent({ agent_id: A1, updates: [upd(G(1), { action: "approve" }), upd(G(2), { action: "inherit" }), upd(G(3)), upd(G(4), { installed: true, action: "approve" })] });
    expect(await executeJob("RESET_APPROVALS", { agentId: A1 }, deps)).toEqual({ reset: 2 });
    expect(a.updates.map((u) => u.action)).toEqual(["nothing", "nothing", "nothing", "approve"]);
  });
});

describe("CACHE_PACKAGE / DEPLOY_PACKAGE", () => {
  const bytes = Buffer.from("MSI-BYTES-".repeat(1000));
  const pkgFor = (b: Buffer, over: Partial<JobPackage> = {}): JobPackage => ({
    kind: "msi",
    wingetId: "7zip.7zip",
    version: "24.08",
    sha256: createHash("sha256").update(b).digest("hex"),
    size: b.length,
    repoPath: "pkgs/7zip/24.08/7z2408-x64.msi",
    publisher: "O=Igor Pavlov",
    switches: "",
    ...over,
  });

  it("caches a package (verified) and is idempotent", async () => {
    pg.addPackage(bytes);
    const pkg = pkgFor(bytes);
    const r = await executeJob("CACHE_PACKAGE", { package: pkg }, deps);
    expect(r).toEqual({ sha256: pkg.sha256, size: pkg.size, cachedPath: pkg.repoPath });
    expect(await readFile(join(dir, "cache", pkg.repoPath))).toEqual(bytes);
    const downloads = pg.packageDownloads.length;
    await executeJob("CACHE_PACKAGE", { package: pkg }, deps);
    expect(pg.packageDownloads.length).toBe(downloads); // served from cache, no second download
  });

  it("rejects bytes that do not match the signed SHA-256 / size, leaving nothing behind", async () => {
    const evil = Buffer.from("EVIL-BYTES".repeat(1000));
    const evilSha = pg.addPackage(evil);
    // the server serves `evil` under its own hash, but the job declares that hash with different bytes' size
    await expectJobError(executeJob("CACHE_PACKAGE", { package: pkgFor(bytes, { sha256: evilSha, size: evil.length - 1 }) }, deps), false, /server sent/);
    // hash collision attempt: same size, wrong content under a known sha
    pg.packages.set("b".repeat(64), evil);
    await expectJobError(executeJob("CACHE_PACKAGE", { package: pkgFor(evil, { sha256: "b".repeat(64) }) }, deps), false, /SHA-256 mismatch/);
    expect(index.list()).toEqual([]);
  });

  it("enforces the size cap and refuses a different SHA-256 for an existing path", async () => {
    await expectJobError(executeJob("CACHE_PACKAGE", { package: pkgFor(bytes, { size: 2 * 1024 * 1024 }) }, deps), false, /maxPackageBytes/);
    pg.addPackage(bytes);
    await executeJob("CACHE_PACKAGE", { package: pkgFor(bytes) }, deps);
    await expectJobError(executeJob("CACHE_PACKAGE", { package: pkgFor(bytes, { sha256: "c".repeat(64) }) }, deps), false, /different SHA-256/);
  });

  it("unknown package on the server is a permanent failure", async () => {
    await expectJobError(executeJob("CACHE_PACKAGE", { package: pkgFor(Buffer.from("nope")) }, deps), false, /404/);
  });

  it("DEPLOY_PACKAGE requires the package in the cache, re-hashes it, runs the fixed script with PG_* env", async () => {
    tactical.addAgent({ agent_id: A1 });
    const pkg = pkgFor(bytes);
    await expectJobError(executeJob("DEPLOY_PACKAGE", { agentId: A1, package: pkg }, deps), true, /not in this site's cache/);

    pg.addPackage(bytes);
    await executeJob("CACHE_PACKAGE", { package: pkg }, deps);
    tactical.onRunScript = async () => "PATCHGATE_RESULT=OK";
    const r = await executeJob("DEPLOY_PACKAGE", { agentId: A1, package: pkg }, deps);
    expect(r).toMatchObject({ outcome: "INSTALLED" });
    expect(tactical.runScripts[0]).toEqual({
      agentId: A1,
      script: 42,
      env: {
        PG_KIND: "msi",
        PG_REPO_URL: "http://127.0.0.1:1/repo",
        PG_PATH: pkg.repoPath,
        PG_SHA256: pkg.sha256,
        PG_APP_ID: "7zip.7zip",
        PG_VERSION: "24.08",
        PG_PUBLISHER: "O=Igor Pavlov",
        PG_ARGS: "",
      },
    });
  });

  it("DEPLOY_PACKAGE refuses a cached file that was tampered with on disk (and evicts it)", async () => {
    tactical.addAgent({ agent_id: A1 });
    const pkg = pkgFor(bytes);
    pg.addPackage(bytes);
    await executeJob("CACHE_PACKAGE", { package: pkg }, deps);
    const tampered = Buffer.from(bytes);
    tampered[0] = 0x58;
    await writeFile(join(dir, "cache", pkg.repoPath), tampered);
    const fresh = await CacheIndex.open(join(dir, "idx.json"), join(dir, "cache"));
    await expectJobError(executeJob("DEPLOY_PACKAGE", { agentId: A1, package: pkg }, { ...deps, index: fresh }), false, /re-check/);
    expect(fresh.get(pkg.repoPath)).toBeUndefined();
    expect(tactical.runScripts).toEqual([]);
  });

  it("maps script results: FAIL is permanent, cache-busy is retryable, agent already current", async () => {
    tactical.addAgent({ agent_id: A1, version: "2.11.0" });
    const pkg = pkgFor(bytes);
    pg.addPackage(bytes);
    await executeJob("CACHE_PACKAGE", { package: pkg }, deps);
    tactical.onRunScript = async () => "PATCHGATE_RESULT=FAIL:signer mismatch";
    await expectJobError(executeJob("DEPLOY_PACKAGE", { agentId: A1, package: pkg }, deps), false, /signer mismatch/);
    tactical.onRunScript = async () => "PATCHGATE_RESULT=FAIL:The remote server returned an error: (503) Server Unavailable.";
    await expectJobError(executeJob("DEPLOY_PACKAGE", { agentId: A1, package: pkg }, deps), true, /503/);

    const agentBytes = Buffer.from("AGENT".repeat(100));
    const agentPkg = pkgFor(agentBytes, {
      kind: "agent",
      wingetId: "Tactical.Agent",
      version: "2.11.0",
      publisher: "",
      repoPath: "tactical/agent/2.11.0/tacticalagent-v2.11.0-windows-amd64.exe",
    });
    pg.addPackage(agentBytes);
    await executeJob("CACHE_PACKAGE", { package: agentPkg }, deps);
    const before = tactical.runScripts.length;
    expect(await executeJob("DEPLOY_PACKAGE", { agentId: A1, package: agentPkg }, deps)).toMatchObject({ outcome: "ALREADY_INSTALLED" });
    expect(tactical.runScripts.length).toBe(before);
  });

  it("DEPLOY_PACKAGE without a configured install script id fails permanently", async () => {
    await expectJobError(executeJob("DEPLOY_PACKAGE", { agentId: A1, package: pkgFor(bytes) }, { ...deps, installScriptId: undefined }), false, /installScriptId/);
  });
});

describe("H5: install outcome unknown (never a second installer)", () => {
  const bytes = Buffer.from("MSI-BYTES-".repeat(100));
  const pkg = (): JobPackage => ({
    kind: "msi",
    wingetId: "7zip.7zip",
    version: "24.08",
    sha256: createHash("sha256").update(bytes).digest("hex"),
    size: bytes.length,
    repoPath: "pkgs/7zip/24.08/7z2408-x64.msi",
    publisher: "O=Igor Pavlov",
    switches: "",
  });
  const unknown = async (p: Promise<unknown>) => {
    const err = await p.then(
      () => null,
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(JobError);
    expect((err as JobError).retryable).toBe(false);
    expect((err as JobError).outcomeUnknown).toBe(true);
    expect((err as JobError).message).toMatch(/result unknown/);
  };

  it("proxy 502/503/504/408 and Tactical's 'timeout' answer are outcome-unknown; 'agent offline' stays retryable", async () => {
    tactical.addAgent({ agent_id: A1 });
    pg.addPackage(bytes);
    await executeJob("CACHE_PACKAGE", { package: pkg() }, deps);
    for (const status of [502, 503, 504, 408]) {
      tactical.runScriptStatus = { status, body: "upstream timed out" };
      await unknown(executeJob("DEPLOY_PACKAGE", { agentId: A1, package: pkg() }, deps));
    }
    tactical.runScriptStatus = undefined;
    tactical.onRunScript = async () => "timeout";
    await unknown(executeJob("DEPLOY_PACKAGE", { agentId: A1, package: pkg() }, deps));
    tactical.runScriptStatus = { status: 400, body: "Unable to contact the agent" };
    await expectJobError(executeJob("DEPLOY_PACKAGE", { agentId: A1, package: pkg() }, deps), true, /400/);
  });
});

describe("LOW: SYNC_AGENTS never truncates", () => {
  it("more agents than the protocol maximum → permanent error instead of a truncated list", async () => {
    for (let i = 0; i < 10_001; i++) tactical.agents.set(`agentX${String(i).padStart(7, "0")}`, { agent_id: `agentX${String(i).padStart(7, "0")}`, hostname: "pc", status: "online", version: "2.10.0", goarch: "amd64", updates: [], software: [] });
    let count = 0;
    await expectJobError(executeJob("SYNC_AGENTS", {}, { ...deps, onAgentCount: (n) => (count = n) }), false, /10001 agents.*Not truncating/);
    expect(count).toBe(10_001);
  });
});

describe("M9: COLLECT results are shrunk to the result limit", () => {
  it("drops software lists and marks the agent instead of producing an oversize result", async () => {
    const software = Array.from({ length: 500 }, (_, i) => ({ name: `App ${i}`, version: "1.0", publisher: "Vendor" }));
    tactical.addAgent({ agent_id: A1, software, updates: [upd(G(1))] });
    tactical.addAgent({ agent_id: A2 });
    const r = (await executeJob("COLLECT", { agentIds: [A1, A2], updates: true, software: true, agent: false }, { ...deps, maxResultBytes: 4000 })) as {
      agents: Array<Record<string, unknown>>;
    };
    expect(r.agents[0]).toMatchObject({ agentId: A1, updates: [{ guid: G(1) }], error: expect.stringMatching(/software list omitted/) });
    expect(r.agents[0]!.software).toBeUndefined();
    expect(JSON.stringify(r).length).toBeLessThanOrEqual(4000);
  });
});

describe("SECURITY #1: local trust policy in CACHE_PACKAGE / DEPLOY_PACKAGE", () => {
  it("refuses a package whose publisher is not pinned locally before downloading or installing anything", async () => {
    tactical.addAgent({ agent_id: A1 });
    const bytes = Buffer.from("EVIL".repeat(100));
    pg.addPackage(bytes);
    const evil: JobPackage = {
      kind: "exe",
      wingetId: "7zip.7zip",
      version: "24.09",
      sha256: createHash("sha256").update(bytes).digest("hex"),
      size: bytes.length,
      repoPath: "pkgs/7zip/24.09/7z.exe",
      publisher: "O=Evil Corp",
      switches: "/S",
    };
    const trusted = { ...deps, trust: { publishers: { "7zip.7zip": ["O=Igor Pavlov"] }, allowUnlistedApps: false } };
    const downloads = pg.packageDownloads.length;
    await expectJobError(executeJob("CACHE_PACKAGE", { package: evil }, trusted), false, /local trust policy/);
    expect(pg.packageDownloads.length).toBe(downloads);
    await executeJob("CACHE_PACKAGE", { package: evil }, deps); // cached by a connector without policy
    await expectJobError(executeJob("DEPLOY_PACKAGE", { agentId: A1, package: evil }, trusted), false, /O=Evil Corp is not pinned locally/);
    expect(tactical.runScripts).toEqual([]);
  });
});
