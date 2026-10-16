import { createHash, generateKeyPairSync } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { CacheDownloader } from "../src/cache/download.ts";
import { CacheIndex } from "../src/cache/cache-index.ts";
import { JobRunner } from "../src/jobs/runner.ts";
import { Journal } from "../src/journal.ts";
import { createPatchGateClient } from "../src/pg-client.ts";
import { rawFromPublicKey, signJob } from "../src/protocol.ts";
import { createTacticalClient } from "../src/tactical/client.ts";
import { silentLogger } from "../src/util/log.ts";
import { Semaphore } from "../src/util/semaphore.ts";
import { tempDir, waitFor } from "./helpers/common.ts";
import { FakePatchGate } from "./helpers/fake-patchgate.ts";
import { FakeTactical } from "./helpers/fake-tactical.ts";

const KEY = "TACTICAL-TEST-KEY-123";
const A1 = "agentAAAA1111";
const SELF = "conn-self";

let dir: string;
let cleanup: () => Promise<void>;
let pg: FakePatchGate;
let tactical: FakeTactical;
let journal: Journal;
let runner: JobRunner;
let deploySem: Semaphore;

async function makeRunner(): Promise<JobRunner> {
  const conn = generateKeyPairSync("ed25519");
  pg.connectors.set(SELF, { publicKey: rawFromPublicKey(conn.publicKey), tenantId: "t1" });
  const pgClient = createPatchGateClient({ serverUrl: pg.url, connectorId: SELF, privateKey: conn.privateKey, timeoutMs: 5000 });
  const index = await CacheIndex.open(join(dir, "idx.json"), join(dir, "cache"));
  journal = await Journal.open(join(dir, "journal.jsonl"), { retentionDays: 30 });
  deploySem = new Semaphore(2);
  return new JobRunner({
    pg: pgClient,
    journal,
    connectorId: SELF,
    jobSigningPublicKey: pg.jobSigningPublicKey,
    deploySem,
    otherSem: new Semaphore(2),
    log: silentLogger,
    postBackoff: { baseMs: 10, maxMs: 50 },
    deps: {
      tactical: createTacticalClient({ baseUrl: tactical.url, apiKey: KEY, timeoutMs: 5000 }),
      index,
      downloader: new CacheDownloader({ pg: pgClient, index, root: join(dir, "cache"), maxPackageBytes: 1 << 20, minFreeBytes: 0, log: silentLogger }),
      cacheBaseUrl: "https://pgcache.bank.local/repo",
      installScriptId: 9,
      installScriptTimeoutSec: 60,
      maxParallelCalls: 4,
      log: silentLogger,
    },
  });
}

beforeEach(async () => {
  ({ dir, cleanup } = await tempDir());
  pg = new FakePatchGate();
  await pg.start();
  tactical = new FakeTactical({ apiKey: KEY });
  await tactical.start();
  tactical.addAgent({ agent_id: A1 });
  runner = await makeRunner();
});
afterEach(async () => {
  await runner.shutdown(1000);
  await journal.close();
  await pg.stop();
  await tactical.stop();
  await cleanup();
});

describe("verifyJob rejection cases (nothing touches Tactical)", () => {
  it("tampered payload: rejected, not executed, not answered", async () => {
    const job = pg.makeJob(SELF, "SCAN", { agentIds: [A1] });
    pg.knownJobs.add(job.id);
    await runner.submit({ ...job, payload: { agentIds: [A1, "agentEVIL9999"] } });
    await runner.idle();
    expect(runner.stats.rejected).toBe(1);
    expect(tactical.calls).toEqual([]);
    expect(pg.resultPosts).toEqual([]);
  });

  it("job signed by another key or for another connector: rejected silently", async () => {
    const rogue = generateKeyPairSync("ed25519");
    const forged = signJob(rogue.privateKey, { ...pg.makeJob(SELF, "SYNC_AGENTS", {}), signature: undefined } as never);
    await runner.submit(forged);
    await runner.submit(pg.makeJob("conn-other", "SYNC_AGENTS", {}));
    await runner.idle();
    expect(runner.stats.rejected).toBe(2);
    expect(tactical.calls).toEqual([]);
    expect(pg.resultPosts).toEqual([]);
  });

  it("authentic but expired / invalid payload / unknown type: answered with a permanent failure", async () => {
    const expired = pg.makeJob(SELF, "SCAN", { agentIds: [A1] }, { expiresAt: new Date(Date.now() - 1000).toISOString() });
    const badPayload = pg.makeJob(SELF, "DEPLOY_WINDOWS", { agentId: A1, guids: ["not-a-guid"], rebootPolicy: "NEVER" });
    const extraField = pg.makeJob(SELF, "SCAN", { agentIds: [A1], script: "calc.exe" });
    const unknownType = pg.makeJob(SELF, "RUN_COMMAND" as never, { cmd: "whoami" });
    for (const j of [expired, badPayload, extraField, unknownType]) {
      pg.knownJobs.add(j.id);
      await runner.submit(j);
    }
    await runner.idle();
    expect(tactical.calls).toEqual([]);
    expect(pg.results.get(expired.id)).toEqual({ ok: false, error: "rejected by connector: job expired", retryable: false });
    expect(pg.results.get(badPayload.id)).toMatchObject({ ok: false, retryable: false, error: expect.stringMatching(/invalid payload/) });
    expect(pg.results.get(extraField.id)).toMatchObject({ ok: false, retryable: false });
    expect(pg.results.get(unknownType.id)).toMatchObject({ ok: false, error: expect.stringMatching(/unknown job type/) });
  });

  it("not-yet-valid job is ignored (no result) until re-delivered", async () => {
    const future = pg.makeJob(SELF, "SCAN", { agentIds: [A1] }, { notBefore: new Date(Date.now() + 3_600_000).toISOString() });
    await runner.submit(future);
    await runner.idle();
    expect(pg.resultPosts).toEqual([]);
    expect(journal.get(future.id)).toBeUndefined();
  });

  it("malformed job objects are dropped", async () => {
    await runner.submit({ hello: "world" });
    await runner.submit(null);
    await runner.submit({ ...pg.makeJob(SELF, "SCAN", { agentIds: [A1] }), id: "../../etc" });
    await runner.idle();
    expect(runner.stats.rejected).toBe(3);
    expect(pg.resultPosts).toEqual([]);
  });
});

describe("idempotency and delivery", () => {
  it("re-delivered (non-read-only) job is not executed twice, even after its body was dropped", async () => {
    const job = pg.makeJob(SELF, "RESET_APPROVALS", { agentId: A1 });
    pg.knownJobs.add(job.id);
    await runner.submit(job);
    await runner.idle();
    const reads = () => tactical.calls.filter((c) => c.path.startsWith("/winupdate/")).length;
    expect(reads()).toBe(1);
    expect(journal.get(job.id)?.result).toBeUndefined(); // acknowledged → only the stub is kept
    expect(journal.get(job.id)?.summary).toEqual({ ok: true });
    await runner.submit(job);
    await runner.idle();
    expect(reads()).toBe(1);
    expect(pg.resultPosts.map((p) => p.status)).toEqual([200, 409]);
    expect(pg.resultPosts[1]!.result).toMatchObject({ ok: false, retryable: false, error: expect.stringMatching(/already executed/) });
    expect(journal.get(job.id)?.postOutcome).toBe("duplicate");
  });

  it("a re-delivered read-only job is simply run again (its body is never journaled)", async () => {
    const job = pg.makeJob(SELF, "SCAN", { agentIds: [A1] });
    pg.knownJobs.add(job.id);
    await runner.submit(job);
    await runner.idle();
    expect(await readFile(journal.file, "utf8")).not.toContain('"requested"');
    await runner.submit(job);
    await runner.idle();
    expect(tactical.calls.filter((c) => c.path.includes("/scan/")).length).toBe(2);
    expect(pg.resultPosts.map((p) => p.status)).toEqual([200, 409]);
  });

  it("retries result posting with backoff until PatchGate accepts", async () => {
    pg.failResultPosts = 3;
    const job = pg.makeJob(SELF, "SYNC_AGENTS", {});
    pg.knownJobs.add(job.id);
    await runner.submit(job);
    await runner.idle();
    expect(pg.results.get(job.id)).toMatchObject({ ok: true });
    expect(journal.unposted()).toEqual([]);
  });

  it("unacknowledged results survive a restart and are re-sent", async () => {
    pg.failResultPosts = 1_000;
    const job = pg.makeJob(SELF, "RESET_APPROVALS", { agentId: A1 });
    pg.knownJobs.add(job.id);
    await runner.submit(job);
    await waitFor(() => journal.get(job.id)?.result);
    await runner.shutdown(50); // posting still failing → aborted, stays in the journal
    await journal.close();

    pg.failResultPosts = 0;
    runner = await makeRunner(); // "restart": reopens the same journal
    expect(runner.resendUnposted()).toBe(1);
    await runner.idle();
    expect(pg.results.get(job.id)).toMatchObject({ ok: true, result: { reset: 0 } });
  });

  it("an unacknowledged read-only result is not journaled; after a restart the re-delivered job runs again", async () => {
    pg.failResultPosts = 1_000;
    const job = pg.makeJob(SELF, "SYNC_AGENTS", {});
    pg.knownJobs.add(job.id);
    await runner.submit(job);
    await waitFor(() => journal.get(job.id)?.doneAt);
    await runner.shutdown(50);
    await journal.close();

    pg.failResultPosts = 0;
    runner = await makeRunner();
    expect(runner.resendUnposted()).toBe(0);
    await runner.submit(job);
    await runner.idle();
    expect(pg.results.get(job.id)).toMatchObject({ ok: true, result: { agents: [{ agentId: A1 }] } });
  });

  it("a DEPLOY_PACKAGE interrupted mid-run is reported as outcome-unknown, never re-run", async () => {
    const job = pg.makeJob(SELF, "DEPLOY_PACKAGE", {
      agentId: A1,
      package: { kind: "msi", wingetId: "a.app", version: "1.0", sha256: "a".repeat(64), size: 5, repoPath: "pkgs/a/1.0/a.msi", publisher: "O=A Corp", switches: "" },
    });
    pg.knownJobs.add(job.id);
    await journal.markStarted(job.id, "DEPLOY_PACKAGE"); // as if the connector died during the install
    await runner.submit(job);
    await runner.idle();
    expect(tactical.runScripts).toEqual([]);
    expect(pg.results.get(job.id)).toMatchObject({ ok: false, retryable: false, outcomeUnknown: true, error: expect.stringMatching(/interrupted/) });
  });

  it("DEPLOY jobs are limited by the deploy semaphore", async () => {
    let active = 0;
    let peak = 0;
    tactical.onRunScript = async () => {
      active++;
      peak = Math.max(peak, active);
      await new Promise((r) => setTimeout(r, 50));
      active--;
      return "PATCHGATE_RESULT=OK";
    };
    const index = (runner as unknown as { o: { deps: { index: CacheIndex } } }).o.deps.index;
    const { mkdir, writeFile } = await import("node:fs/promises");
    const { createHash } = await import("node:crypto");
    const bytes = Buffer.from("x");
    await mkdir(join(dir, "cache", "pkgs/a/1.0"), { recursive: true });
    await writeFile(join(dir, "cache", "pkgs/a/1.0/a.msi"), bytes);
    const sha = createHash("sha256").update(bytes).digest("hex");
    await index.put({ repoPath: "pkgs/a/1.0/a.msi", sha256: sha, size: 1, kind: "msi", wingetId: "a.app", version: "1.0", cachedAt: "" });
    const ids = [];
    for (let i = 0; i < 6; i++) {
      const id = `agentPC${String(i).padStart(6, "0")}`;
      tactical.addAgent({ agent_id: id });
      const job = pg.makeJob(SELF, "DEPLOY_PACKAGE", {
        agentId: id,
        package: { kind: "msi", wingetId: "a.app", version: "1.0", sha256: sha, size: 1, repoPath: "pkgs/a/1.0/a.msi", publisher: "O=A Corp", switches: "" },
      });
      pg.knownJobs.add(job.id);
      ids.push(job.id);
      await runner.submit(job);
    }
    await runner.idle();
    expect(peak).toBe(2);
    expect(ids.every((id) => pg.results.get(id)?.ok === true)).toBe(true);
  });
});

describe("outcome-unknown installs, late starts, result posting limits", () => {
  const PKG_BYTES = Buffer.from("x");
  const pkg = () => ({
    kind: "msi" as const,
    wingetId: "a.app",
    version: "1.0",
    sha256: createHash("sha256").update(PKG_BYTES).digest("hex"),
    size: 1,
    repoPath: "pkgs/a/1.0/a.msi",
    publisher: "O=A Corp",
    switches: "",
  });
  const cachePkg = async () => {
    const index = (runner as unknown as { o: { deps: { index: CacheIndex } } }).o.deps.index;
    await mkdir(join(dir, "cache", "pkgs/a/1.0"), { recursive: true });
    await writeFile(join(dir, "cache", "pkgs/a/1.0/a.msi"), PKG_BYTES);
    await index.put({ repoPath: "pkgs/a/1.0/a.msi", sha256: pkg().sha256, size: 1, kind: "msi", wingetId: "a.app", version: "1.0", cachedAt: "" });
    return index;
  };

  it("H5: a proxy 504 on runscript (script still running) is outcome-unknown, not retryable, and never re-run", async () => {
    await cachePkg();
    tactical.runScriptStatus = { status: 504, body: "Gateway Time-out" };
    const job = pg.makeJob(SELF, "DEPLOY_PACKAGE", { agentId: A1, package: pkg() });
    pg.knownJobs.add(job.id);
    await runner.submit(job);
    await runner.idle();
    expect(pg.results.get(job.id)).toMatchObject({ ok: false, retryable: false, outcomeUnknown: true, error: expect.stringMatching(/result unknown/) });
    tactical.runScriptStatus = undefined;
    await runner.submit(job); // PatchGate re-delivers: the installer must not start a second time
    await runner.idle();
    expect(tactical.runScripts).toHaveLength(1);
    expect(pg.resultPosts[1]!.result).toMatchObject({ ok: false, outcomeUnknown: true });
  });

  it("M2: a job whose window closes while it waits for a slot is reported 'expired before start', never run", async () => {
    await cachePkg();
    await deploySem.acquire();
    await deploySem.acquire(); // both install slots busy
    const job = pg.makeJob(SELF, "DEPLOY_PACKAGE", { agentId: A1, package: pkg() }, { expiresAt: new Date(Date.now() + 300).toISOString() });
    pg.knownJobs.add(job.id);
    await runner.submit(job);
    await new Promise((r) => setTimeout(r, 450));
    deploySem.release();
    deploySem.release();
    await runner.idle();
    expect(tactical.runScripts).toEqual([]);
    expect(pg.results.get(job.id)).toMatchObject({ ok: false, retryable: false, error: expect.stringMatching(/expired before start/) });
    expect(runner.stats.expiredBeforeStart).toBe(1);
    expect(journal.get(job.id)?.startedAt).toBeUndefined();
  });

  it("M9: 413 → a small permanent-failure stub is posted instead of looping", async () => {
    pg.resultStatusQueue.push(413);
    const job = pg.makeJob(SELF, "RESET_APPROVALS", { agentId: A1 });
    pg.knownJobs.add(job.id);
    await runner.submit(job);
    await runner.idle();
    expect(pg.resultAttempts).toBe(2);
    expect(pg.results.get(job.id)).toEqual({ ok: false, retryable: false, error: expect.stringMatching(/result too large/) });
    expect(journal.unposted()).toEqual([]);
  });

  it("M9: non-retryable statuses (403) stop the retry loop; the result stays journaled for the next start", async () => {
    pg.resultStatusQueue.push(403);
    const job = pg.makeJob(SELF, "RESET_APPROVALS", { agentId: A1 });
    pg.knownJobs.add(job.id);
    await runner.submit(job);
    await runner.idle();
    expect(pg.resultAttempts).toBe(1);
    expect(runner.stats.postFailedPermanently).toBe(1);
    expect(journal.unposted().map((s) => s.jobId)).toEqual([job.id]);
  });

  it("SEC#16: an authentic job valid for more than 72 h gets a permanent failure; a forged one gets nothing", async () => {
    const now = Date.now();
    const long = pg.makeJob(SELF, "SCAN", { agentIds: [A1] }, { notBefore: new Date(now - 60_000).toISOString(), expiresAt: new Date(now + 73 * 3_600_000).toISOString() });
    pg.knownJobs.add(long.id);
    await runner.submit(long);
    const rogue = generateKeyPairSync("ed25519");
    const forged = signJob(rogue.privateKey, { ...pg.makeJob(SELF, "SCAN", { agentIds: [A1] }, { expiresAt: new Date(now + 100 * 3_600_000).toISOString() }), signature: undefined } as never);
    pg.knownJobs.add(forged.id);
    await runner.submit(forged);
    await runner.idle();
    expect(tactical.calls).toEqual([]);
    expect(pg.results.get(long.id)).toEqual({ ok: false, retryable: false, error: "rejected by connector: job lifetime too long" });
    expect(pg.results.has(forged.id)).toBe(false);
  });

  it("M12: verified jobs pin their packages in the cache index until they expire", async () => {
    const index = await cachePkg();
    const job = pg.makeJob(SELF, "DEPLOY_PACKAGE", { agentId: A1, package: pkg() });
    tactical.onRunScript = async () => "PATCHGATE_RESULT=OK";
    pg.knownJobs.add(job.id);
    await runner.submit(job);
    await runner.idle();
    expect(index.pinnedUntil(pkg().repoPath)).toBe(Date.parse(job.expiresAt));
  });
});
