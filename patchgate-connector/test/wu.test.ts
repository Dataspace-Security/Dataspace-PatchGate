import { createHash, generateKeyPairSync } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { CacheDownloader } from "../src/cache/download.ts";
import { CacheIndex } from "../src/cache/cache-index.ts";
import { JobError } from "../src/jobs/errors.ts";
import { executeJob, isDeployJob, isNonIdempotent, type ExecutorDeps } from "../src/jobs/executors.ts";
import { UPDATE_ENTRY_RE, batchUpdates, extractResultJson, parseInstallOutput, parseScanOutput, updateEntries } from "../src/jobs/wu-parse.ts";
import { createPatchGateClient } from "../src/pg-client.ts";
import { rawFromPublicKey, resultSchemas, type JobPackage } from "../src/protocol.ts";
import { createTacticalClient } from "../src/tactical/client.ts";
import { silentLogger } from "../src/util/log.ts";
import { tempDir } from "./helpers/common.ts";
import { FakePatchGate } from "./helpers/fake-patchgate.ts";
import { FakeTactical, type RunScriptCall } from "./helpers/fake-tactical.ts";

const KEY = "TACTICAL-TEST-KEY-123";
const A1 = "agentAAAA1111";
const A2 = "agentBBBB2222";
const U1 = "11111111-2222-4333-8444-555555555555";
const U2 = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
const SHA1 = "5c27f9ceebeb31e1c962db9a4cd889a712b193c3";
const sha = (b: Buffer) => createHash("sha256").update(b).digest("hex");

let tactical: FakeTactical;
let pg: FakePatchGate;
let dir: string;
let cleanup: () => Promise<void>;
let deps: ExecutorDeps;

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
  const index = await CacheIndex.open(join(dir, "idx.json"), root);
  deps = {
    tactical: createTacticalClient({ baseUrl: tactical.url, apiKey: KEY, timeoutMs: 5000 }),
    index,
    downloader: new CacheDownloader({ pg: pgClient, index, root, maxPackageBytes: 1024 * 1024, minFreeBytes: 0, log: silentLogger }),
    cacheBaseUrl: "https://connector.bank.local:8443/repo",
    installScriptTimeoutSec: 60,
    maxParallelCalls: 4,
    wu: { scanScriptId: 77, installScriptId: 78, scanTimeoutSec: 3600, installTimeoutSec: 1800 },
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

const cabBytes = Buffer.from("MSCF-wsusscn2".repeat(500));
const scanCab = (): JobPackage => ({
  kind: "wsusscan",
  wingetId: "Microsoft.WsusScan",
  version: "20261014-3ac6fe2a",
  sha256: sha(cabBytes),
  size: cabBytes.length,
  repoPath: `winupdate/wsusscan/${sha(cabBytes).slice(0, 16)}/wsusscn2.cab`,
  publisher: "O=Microsoft Corporation",
  switches: "",
});
const fileBytes = (n: string) => Buffer.from(`MSCF-update-${n}`.repeat(300));
const filePkg = (updateId: string, name: string, kind: "msu" | "cab" = "msu"): JobPackage => {
  const b = fileBytes(name);
  return { kind, wingetId: "Microsoft.WindowsUpdate", version: "KB5099999", sha256: sha(b), size: b.length, repoPath: `winupdate/${updateId}/${name}.${kind}`, publisher: "O=Microsoft Corporation", switches: "" };
};
async function cache(pkg: JobPackage, bytes: Buffer) {
  pg.addPackage(bytes);
  await executeJob("CACHE_PACKAGE", { package: pkg }, deps);
}

const scanLine = (updates: unknown[]) => `scan log\nPATCHGATE_RESULT=${JSON.stringify({ ok: true, updates })}\n`;
const scanUpdate = {
  updateId: U1,
  revision: 200,
  kb: "KB5099999",
  title: "2026-10 Cumulative Update",
  msrcSeverity: "Critical",
  classification: "Security Updates",
  files: [{ url: `http://download.windowsupdate.com/c/msdownload/update/software/secu/2026/10/x_${SHA1}.msu`, name: `x_${SHA1}.msu`, size: 0, sha1: SHA1, sha256: null }],
};

describe("WU_SCAN", () => {
  it("caches wsusscn2.cab kind wsusscan and runs the scan script per agent with fixed env", async () => {
    await cache(scanCab(), cabBytes);
    tactical.addAgent({ agent_id: A1 });
    tactical.addAgent({ agent_id: A2 });
    tactical.onRunScript = async (c: RunScriptCall) =>
      c.agentId === A1 ? scanLine([scanUpdate]) : `PATCHGATE_RESULT=${JSON.stringify({ ok: false, error: "Windows Update service is disabled" })}`;
    const r = (await executeJob("WU_SCAN", { agentIds: [A1, A2], scanCab: scanCab() }, deps)) as { agents: Array<{ agentId: string; updates?: unknown[]; error?: string }> };
    expect(resultSchemas.WU_SCAN.safeParse(r).success).toBe(true);
    expect(r.agents.find((a) => a.agentId === A1)?.updates).toHaveLength(1);
    expect(r.agents.find((a) => a.agentId === A2)?.error).toMatch(/disabled/);
    expect(tactical.runScripts.map((c) => c.script)).toEqual([77, 77]);
    expect(tactical.runScripts[0]!.env).toEqual({
      PG_REPO_URL: "https://connector.bank.local:8443/repo",
      PG_PATH: scanCab().repoPath,
      PG_SHA256: scanCab().sha256,
      PG_SCAN_TIMEOUT_SEC: "3480",
    });
  });

  it("refuses when the cab is not cached, not configured, or not the Microsoft scan package", async () => {
    tactical.addAgent({ agent_id: A1 });
    await expectJobError(executeJob("WU_SCAN", { agentIds: [A1], scanCab: scanCab() }, deps), true, /not in this site's cache/);
    await expectJobError(executeJob("WU_SCAN", { agentIds: [A1], scanCab: scanCab() }, { ...deps, wu: undefined }), false, /wuScanScriptId/);
    await expectJobError(executeJob("WU_SCAN", { agentIds: [A1], scanCab: { ...scanCab(), wingetId: "Evil.Pkg" } }, deps), false, /Microsoft wsusscan/);
    await expectJobError(executeJob("WU_SCAN", { agentIds: [A1], scanCab: { ...scanCab(), repoPath: "winupdate/wsusscan/x/other.cab" } }, deps), false, /repoPath/);
    expect(tactical.runScripts).toHaveLength(0);
  });

  it("turns malformed PC output into a per-agent error, never a crash", async () => {
    await cache(scanCab(), cabBytes);
    tactical.addAgent({ agent_id: A1 });
    tactical.onRunScript = async () => scanLine([{ ...scanUpdate, updateId: "not-a-guid" }]);
    const r = (await executeJob("WU_SCAN", { agentIds: [A1], scanCab: scanCab() }, deps)) as { agents: Array<{ error?: string }> };
    expect(r.agents[0]!.error).toMatch(/invalid scan output at 0\.updateId/);
  });

  it("fails retryable when Tactical is unreachable for every agent", async () => {
    await cache(scanCab(), cabBytes);
    await tactical.stop();
    await expectJobError(executeJob("WU_SCAN", { agentIds: [A1], scanCab: scanCab() }, deps), true, /Tactical unreachable/);
    await tactical.start();
  });
});

describe("WU_INSTALL", () => {
  const ssu = filePkg(U1, "ssu");
  const lcu = filePkg(U1, "lcu");
  const other = filePkg(U2, "other", "cab");
  const payload = (rebootPolicy: "NEVER" | "IF_REQUIRED" | "FORCE" = "IF_REQUIRED") => ({
    agentId: A1,
    updates: [
      { updateId: U1, kb: "KB5099999", files: [ssu, lcu] },
      { updateId: U2, kb: null, files: [other] },
    ],
    rebootPolicy,
  });
  const cacheAll = async () => {
    await cache(ssu, fileBytes("ssu"));
    await cache(lcu, fileBytes("lcu"));
    await cache(other, fileBytes("other"));
  };
  const result = (o: Record<string, unknown>) => `PATCHGATE_RESULT=${JSON.stringify({ ok: true, installed: [], skipped: [], failed: [], rebootRequired: false, rebootScheduled: false, ...o })}`;

  it("passes ordered files in PG_UPDATES and maps per-update outcomes", async () => {
    await cacheAll();
    tactical.addAgent({ agent_id: A1 });
    tactical.onRunScript = async () => result({ installed: [U1], skipped: [U2], rebootRequired: true });
    const r = await executeJob("WU_INSTALL", payload(), deps);
    expect(r).toEqual({ outcome: "INSTALLED", installed: [U1, U2], failed: [], rebootRequired: true });
    const env = tactical.runScripts[0]!.env;
    expect(tactical.runScripts[0]!.script).toBe(78);
    expect(env.PG_REBOOT).toBe("IF_REQUIRED");
    expect(env.PG_DEADLINE_SEC).toBe("1680");
    expect(env.PG_UPDATES!.split(";")).toEqual([
      `${U1},KB5099999,msu,${ssu.sha256},${ssu.size},${ssu.repoPath}`,
      `${U1},KB5099999,msu,${lcu.sha256},${lcu.size},${lcu.repoPath}`,
      `${U2},-,cab,${other.sha256},${other.size},${other.repoPath}`,
    ]);
  });

  it("reports PARTIAL / NOTHING_TO_DO", async () => {
    await cacheAll();
    tactical.addAgent({ agent_id: A1 });
    tactical.onRunScript = async () => result({ installed: [U1], failed: [{ updateId: U2, error: "installer exit 0x80070643" }] });
    expect(await executeJob("WU_INSTALL", payload(), deps)).toEqual({ outcome: "PARTIAL", installed: [U1], failed: [{ updateId: U2, error: "installer exit 0x80070643" }], rebootRequired: false });
    tactical.onRunScript = async () => result({ skipped: [U1, U2] });
    expect(await executeJob("WU_INSTALL", payload(), deps)).toMatchObject({ outcome: "NOTHING_TO_DO", installed: [U1, U2] });
  });

  it("batches large jobs; only the last run may restart the PC", async () => {
    const many = Array.from({ length: 40 }, (_, i) => {
      const id = `${String(i).padStart(8, "0")}-0000-4000-8000-000000000000`;
      return { updateId: id, kb: null, files: [filePkg(id, `f${i}`)] };
    });
    for (const [i, u] of many.entries()) await cache(u.files[0]!, fileBytes(`f${i}`));
    tactical.addAgent({ agent_id: A1 });
    tactical.onRunScript = async (c) => result({ installed: c.env.PG_UPDATES!.split(";").map((e) => e.slice(0, 36)) });
    const r = (await executeJob("WU_INSTALL", { agentId: A1, updates: many, rebootPolicy: "FORCE" }, deps)) as { installed: string[] };
    expect(r.installed).toHaveLength(40);
    expect(tactical.runScripts.length).toBeGreaterThan(1);
    expect(tactical.runScripts.map((c) => c.env.PG_REBOOT)).toEqual([...Array(tactical.runScripts.length - 1).fill("NEVER"), "FORCE"]);
    for (const c of tactical.runScripts) expect(c.env.PG_UPDATES!.length).toBeLessThanOrEqual(6000);
  });

  it("refuses non-Microsoft packages, foreign paths and uncached files before touching the PC", async () => {
    tactical.addAgent({ agent_id: A1 });
    await expectJobError(executeJob("WU_INSTALL", payload(), deps), true, /not in this site's cache/);
    const bad = { ...payload(), updates: [{ updateId: U1, kb: null, files: [{ ...ssu, publisher: "O=Evil Corp" }] }] };
    await expectJobError(executeJob("WU_INSTALL", bad, deps), false, /not a Microsoft update package/);
    const foreign = { ...payload(), updates: [{ updateId: U1, kb: null, files: [{ ...other }] }] };
    await expectJobError(executeJob("WU_INSTALL", foreign, deps), false, /does not belong/);
    const msi = { ...payload(), updates: [{ updateId: U1, kb: null, files: [{ ...ssu, kind: "msi" as const }] }] };
    await expectJobError(executeJob("WU_INSTALL", msi, deps), false, /kind msi not allowed/);
    await expectJobError(executeJob("WU_INSTALL", payload(), { ...deps, wu: { ...deps.wu!, installScriptId: undefined } }), false, /wuInstallScriptId/);
    expect(tactical.runScripts).toHaveLength(0);
  });

  it("an input error from the script fails the job permanently", async () => {
    await cacheAll();
    tactical.addAgent({ agent_id: A1 });
    tactical.onRunScript = async () => `PATCHGATE_RESULT=${JSON.stringify({ ok: false, error: "invalid PG_UPDATES" })}`;
    await expectJobError(executeJob("WU_INSTALL", payload(), deps), false, /invalid PG_UPDATES/);
  });

  it("H5: a proxy gateway error or Tactical 'timeout' on the first run is outcome-unknown (no retry, no 2nd run)", async () => {
    await cacheAll();
    tactical.addAgent({ agent_id: A1 });
    for (const status of [503, 504]) {
      tactical.runScriptStatus = { status, body: "gateway" };
      const err = await executeJob("WU_INSTALL", payload(), deps).then(
        () => null,
        (e: unknown) => e as JobError,
      );
      expect(err).toMatchObject({ retryable: false, outcomeUnknown: true, message: expect.stringMatching(/result unknown/) });
    }
    tactical.runScriptStatus = undefined;
    tactical.onRunScript = async () => "timeout";
    const err = await executeJob("WU_INSTALL", payload(), deps).then(
      () => null,
      (e: unknown) => e as JobError,
    );
    expect(err).toMatchObject({ retryable: false, outcomeUnknown: true });
    expect(tactical.runScripts).toHaveLength(3); // one run per attempt, never a second run inside a job
  });

  it("counts as a deploy job (install cap) and is never re-run after an interruption", () => {
    expect(isDeployJob("WU_INSTALL")).toBe(true);
    expect(isNonIdempotent("WU_INSTALL")).toBe(true); // an interrupted run may still be running on the PC
    expect(isDeployJob("WU_SCAN")).toBe(false);
  });
});

describe("wu-parse", () => {
  it("extracts the last result line, also from JSON-quoted Tactical output", () => {
    expect(extractResultJson('x\nPATCHGATE_RESULT={"ok":true,"updates":[]}\n')).toEqual({ ok: true, updates: [] });
    expect(extractResultJson(JSON.stringify('PATCHGATE_RESULT={"ok":false,"error":"e"}'))).toEqual({ ok: false, error: "e" });
    expect(() => extractResultJson("nothing")).toThrow(/no result line/);
    expect(parseScanOutput(A1, "PATCHGATE_RESULT={bad")).toEqual({ agentId: A1, error: "result line is not valid JSON" });
    expect(parseInstallOutput('PATCHGATE_RESULT={"ok":true}')).toEqual({ ok: false, error: "unexpected install script output" });
  });

  it("builds entries the install script accepts", () => {
    const e = updateEntries({ updateId: U1.toUpperCase(), kb: "KB5099999", files: [filePkg(U1, "a")] });
    expect(UPDATE_ENTRY_RE.test(e[0]!)).toBe(true);
    expect(batchUpdates([{ updateId: U1, entries: ["x".repeat(10)] }, { updateId: U2, entries: ["y".repeat(10)] }], 15)).toHaveLength(2);
  });

  const ps = resolve(__dirname, "../../patchgate-web/scripts/endpoint/Install-PatchGateWinUpdate.ps1");
  it.runIf(existsSync(ps))("PG_UPDATES regex matches the install script's $FileRe", () => {
    const text = readFileSync(ps, "utf8");
    const guid = /^\$Guid = '([^']+)'/m.exec(text)![1]!;
    const fileRe = /^\$FileRe = "([^"]+)"/m.exec(text)![1]!.replaceAll("$Guid", guid);
    expect(new RegExp(`^${fileRe}$`).source).toBe(UPDATE_ENTRY_RE.source);
  });
});
