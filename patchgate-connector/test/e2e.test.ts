import { createHash } from "node:crypto";
import { readFile, stat, writeFile } from "node:fs/promises";
import { request as httpsRequest } from "node:https";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { runChecks } from "../src/check.ts";
import { ConfigError, loadConfig, requireEnrolled } from "../src/config.ts";
import { jobKeyFingerprint, runInit } from "../src/init.ts";
import type { JobPackage, SignedJob } from "../src/protocol.ts";
import { startService, type ServiceHandle } from "../src/service.ts";
import { silentLogger } from "../src/util/log.ts";
import { freePort, TLS, tempDir, waitFor } from "./helpers/common.ts";
import { FakePatchGate } from "./helpers/fake-patchgate.ts";
import { FakeTactical } from "./helpers/fake-tactical.ts";

/**
 * End-to-end: real connector (init + service) against an in-process FAKE PatchGate implementing the
 * protocol over TLS (pinned test CA) and a FAKE Tactical whose "PC" downloads from the connector cache.
 */

const API_KEY = "tactical-e2e-api-key-0001";
const PC = "agentPC000001";

let dir: string;
let cleanup: () => Promise<void>;
let pg: FakePatchGate;
let tactical: FakeTactical;
let configPath: string;
let cachePort: number;
let svc: ServiceHandle | undefined;
let connectorId = "";
let deployJob: SignedJob | undefined;

const PKG_BYTES = Buffer.from("PATCHGATE-TEST-MSI-".repeat(20_000)); // ~380 kB
const pkg = (): JobPackage => ({
  kind: "msi",
  wingetId: "Notepad++.Notepad++",
  version: "8.7.1",
  sha256: createHash("sha256").update(PKG_BYTES).digest("hex"),
  size: PKG_BYTES.length,
  repoPath: "pkgs/Notepad_Notepad_/8.7.1/npp.8.7.1.Installer.x64.msi", // PatchGate sanitises + in paths
  publisher: "O=Notepad++",
  switches: "",
});

function cacheGet(path: string, method = "GET"): Promise<number> {
  return new Promise((resolve, reject) => {
    const req = httpsRequest({ host: "localhost", port: cachePort, path, method, ca: TLS.ca, agent: false }, (res) => {
      res.resume();
      res.on("end", () => resolve(res.statusCode ?? 0));
    });
    req.on("error", reject);
    req.end();
  });
}

beforeAll(async () => {
  ({ dir, cleanup } = await tempDir("pgc-e2e-"));
  pg = new FakePatchGate({ cert: TLS.cert, key: TLS.key });
  await pg.start();
  tactical = new FakeTactical({ apiKey: API_KEY, tls: { cert: TLS.cert, key: TLS.key }, pcCa: TLS.ca });
  await tactical.start();
  tactical.addAgent({ agent_id: PC });
  cachePort = await freePort();

  await writeFile(join(dir, "tactical.key"), API_KEY);
  configPath = join(dir, "connector.json");
  await writeFile(
    configPath,
    JSON.stringify({
      stateDir: join(dir, "state"),
      logLevel: "warn",
      tactical: { url: tactical.url, apiKeyFile: "tactical.key", caFile: TLS.caFile, installScriptId: 77, statusIntervalSec: 1 },
      cache: {
        baseUrl: `https://localhost:${cachePort}/repo`,
        listenHost: "127.0.0.1",
        port: cachePort,
        tls: { certFile: TLS.certFile, keyFile: TLS.keyFile },
        maxConcurrentDownloads: 4,
        perClientConcurrency: 2,
        minFreeBytes: 0,
      },
      limits: { heartbeatIntervalSec: 1, pollWaitSec: 1, shutdownGraceSec: 5 },
    }),
  );
});

afterAll(async () => {
  await svc?.stop();
  await pg.stop();
  await tactical.stop();
  await cleanup();
});

describe("connector end-to-end", () => {
  it("init refuses http:// without --insecure-dev and invalid codes", async () => {
    const base = { configPath, caFile: TLS.caFile, force: false, version: "1.0.0", log: silentLogger, jobKeyFingerprint: jobKeyFingerprint(pg.jobSigningPublicKey) };
    await expect(runInit({ ...base, serverUrl: "http://pg.example.com", code: pg.addEnrollCode(), insecureDev: false })).rejects.toThrow(ConfigError);
    await expect(runInit({ ...base, serverUrl: pg.url, code: "not-a-code", insecureDev: false })).rejects.toThrow(/enrolment code/);
    await expect(runInit({ ...base, serverUrl: pg.url, code: "AAAA-BBBB-CCCC-DDDD-EEEE", insecureDev: false })).rejects.toThrow(/403/);
  });

  it("init requires --job-key-fingerprint (no trust on first use) and refuses a mismatching job key", async () => {
    const base = { configPath, serverUrl: pg.url, caFile: TLS.caFile, insecureDev: false, force: false, version: "1.0.0", log: silentLogger };
    await expect(runInit({ ...base, code: pg.addEnrollCode() })).rejects.toThrow(/--job-key-fingerprint/);
    await expect(runInit({ ...base, code: pg.addEnrollCode(), jobKeyFingerprint: "abc" })).rejects.toThrow(/64-hex-digit/);
    const enrolledBefore = pg.connectors.size;
    await expect(runInit({ ...base, code: pg.addEnrollCode(), jobKeyFingerprint: "f".repeat(64) })).rejects.toThrow(/fingerprint mismatch/);
    expect(pg.connectors.size).toBe(enrolledBefore + 1); // the server enrolled it, but nothing was pinned locally
    expect(JSON.parse(await readFile(configPath, "utf8")).identity).toBeUndefined();
    await expect(readFile(join(dir, "state", "connector-key.pem"))).rejects.toThrow();
  });

  it("enrols: local Ed25519 key (0600), proof of possession, pinned job key", async () => {
    const code = pg.addEnrollCode("tenant-bank-a");
    // operators may paste the fingerprint upper-case with colons
    const fp = jobKeyFingerprint(pg.jobSigningPublicKey).toUpperCase().match(/../g)!.join(":");
    const cfg = await runInit({ configPath, serverUrl: pg.url, code, caFile: TLS.caFile, jobKeyFingerprint: fp, insecureDev: false, force: false, version: "1.0.0", log: silentLogger });
    connectorId = cfg.identity.connectorId;
    expect(pg.connectors.has(connectorId)).toBe(true);
    expect(cfg.identity.tenantId).toBe("tenant-bank-a");
    expect(cfg.identity.jobSigningPublicKey).toBe(pg.jobSigningPublicKey);
    const keyPem = await readFile(cfg.identity.privateKeyFile, "utf8");
    expect(keyPem).toContain("PRIVATE KEY");
    if (process.platform !== "win32") expect((await stat(cfg.identity.privateKeyFile)).mode & 0o777).toBe(0o600);
    expect(await readFile(configPath, "utf8")).not.toContain("PRIVATE KEY");
    // single-use code; already enrolled without --force
    await expect(runInit({ configPath, serverUrl: pg.url, code, caFile: TLS.caFile, jobKeyFingerprint: fp, insecureDev: false, force: false, version: "1.0.0", log: silentLogger })).rejects.toThrow(/already enrolled/);
  });

  it("check: every probe passes against the fakes", async () => {
    const results = await runChecks(await loadConfig(configPath), "1.0.0");
    expect(results.filter((r) => !r.ok)).toEqual([]);
    expect(results.map((r) => r.check)).toEqual(["config", "enrolled", "stateDir", "cacheDir", "cacheTls", "tactical", "patchgate"]);
  });

  it("runs: heartbeat applies PatchGate limits", async () => {
    pg.heartbeatResponse = { maxConcurrentInstalls: 3, bandwidthLimitMbps: 80 };
    svc = await startService(requireEnrolled(await loadConfig(configPath)), { log: silentLogger, version: "1.0.0" });
    const hb = await waitFor(() => pg.heartbeats.find((h) => h.siem !== undefined)); // (the check above sent one without siem)
    expect(svc.limits()).toEqual({ maxConcurrentInstalls: 3, bandwidthLimitMbps: 80 });
    expect(hb).toMatchObject({ version: "1.0.0", cacheBaseUrl: `https://localhost:${cachePort}/repo`, cache: { freeBytes: expect.any(Number) }, tactical: { reachable: true, agents: 1 }, siem: { configured: false } });
  });

  it("CACHE_PACKAGE → DEPLOY_PACKAGE: PC installs from the site cache; result recorded", async () => {
    const p = pkg();
    pg.addPackage(PKG_BYTES);
    const cacheJob = pg.makeJob(connectorId, "CACHE_PACKAGE", { package: p });
    pg.enqueue(cacheJob);
    const cacheResult = await waitFor(() => pg.results.get(cacheJob.id));
    expect(cacheResult).toEqual({ ok: true, result: { sha256: p.sha256, size: p.size, cachedPath: p.repoPath } });
    expect(await readFile(join(dir, "state", "cache", p.repoPath))).toEqual(PKG_BYTES);

    deployJob = pg.makeJob(connectorId, "DEPLOY_PACKAGE", { agentId: PC, package: p });
    pg.enqueue(deployJob);
    const deployResult = await waitFor(() => pg.results.get(deployJob!.id));
    expect(deployResult).toMatchObject({ ok: true, result: { outcome: "INSTALLED" } });
    expect(tactical.runScripts).toHaveLength(1);
    expect(tactical.runScripts[0]).toMatchObject({
      agentId: PC,
      script: 77,
      env: { PG_REPO_URL: `https://localhost:${cachePort}/repo`, PG_PATH: p.repoPath, PG_SHA256: p.sha256, PG_KIND: "msi" },
    });
    await waitFor(() => pg.heartbeats.some((h) => h.cache.files === 1 && h.cache.bytes === p.size));
  });

  it("a tampered job is rejected and never reaches Tactical", async () => {
    const before = tactical.calls.length;
    const job = pg.makeJob(connectorId, "RESET_APPROVALS", { agentId: PC });
    pg.enqueue({ ...job, payload: { agentId: "agentEVIL0001" } });
    await waitFor(() => svc!.runner.stats.rejected >= 1);
    await new Promise((r) => setTimeout(r, 200));
    expect(tactical.calls.slice(before).filter((c) => c.path.includes("winupdate"))).toEqual([]);
    expect(pg.results.has(job.id)).toBe(false);
  });

  it("a re-delivered job is not re-executed (stored result re-sent)", async () => {
    const job = deployJob!;
    pg.enqueue(job); // PatchGate (or a standby lease) delivers the very same signed job again
    await waitFor(() => pg.resultPosts.filter((r) => r.jobId === job.id).length === 2);
    expect(pg.resultPosts.filter((r) => r.jobId === job.id).map((r) => r.status)).toEqual([200, 409]);
    expect(tactical.runScripts).toHaveLength(1);
  });

  it("the cache server only serves verified files and enforces its limits", async () => {
    const p = pkg();
    expect(await cacheGet(`/repo/${p.repoPath}`)).toBe(200);
    expect(await cacheGet(`/repo/${p.repoPath}`, "HEAD")).toBe(200);
    expect(await cacheGet("/repo/pkgs/unknown/1.0/x.msi")).toBe(404);
    expect(await cacheGet("/repo/pkgs/../../connector.json")).toBe(404);
    expect(await cacheGet(`/repo/${p.repoPath}`, "DELETE")).toBe(405);
    expect(await cacheGet("/healthz")).toBe(200);
    expect(svc!.cacheServer.stats().servedTotal).toBeGreaterThanOrEqual(2);
  });

  it("Tactical natsdown: the job is retryable and the heartbeat reports tacticalHealth natsdown; the watchdog's ok clears it", async () => {
    tactical.onRunScript = async () => "natsdown";
    try {
      const job = pg.makeJob(connectorId, "DEPLOY_PACKAGE", { agentId: PC, package: pkg() });
      pg.enqueue(job);
      const res = await waitFor(() => pg.results.get(job.id));
      expect(res).toMatchObject({ ok: false, retryable: true });
      expect(res).not.toHaveProperty("outcomeUnknown");
      const hb = await waitFor(() => pg.heartbeats.find((h) => h.tacticalHealth?.state === "natsdown"));
      expect(hb.tacticalHealth).toMatchObject({ state: "natsdown", since: expect.any(String), watchdog: null });
      expect(Date.parse(hb.tacticalHealth!.since!)).toBeLessThanOrEqual(Date.now());
      // the site watchdog (tactical-health.json next to connector.json) later sees nats-server running again
      await writeFile(
        join(dir, "tactical-health.json"),
        JSON.stringify({ v: 1, nats: "ok", since: null, checkedAt: new Date(Date.now() + 1000).toISOString(), restartsLastHour: 1, lastRestartAt: new Date().toISOString(), detail: "recovered by the watchdog" }),
      );
      const after = pg.heartbeats.length;
      const ok = await waitFor(() => pg.heartbeats.slice(after).find((h) => h.tacticalHealth?.state === "ok"));
      expect(ok.tacticalHealth?.watchdog).toMatchObject({ nats: "ok", restartsLastHour: 1 });
    } finally {
      tactical.onRunScript = undefined;
    }
  });

  it("every request the connector made passed signature, timestamp and nonce checks", () => {
    expect(pg.authFailures).toEqual([]);
    expect(pg.nonces.size).toBeGreaterThan(5);
  });

  it("shuts down gracefully", async () => {
    await svc!.stop();
    svc = undefined;
    await expect(cacheGet("/healthz")).rejects.toThrow();
  });
});
