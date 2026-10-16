import { generateKeyPairSync } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { CacheDownloader } from "../src/cache/download.ts";
import { CacheIndex } from "../src/cache/cache-index.ts";
import { AllowSet, OWN_APPROVAL_MEMORY_MS } from "../src/guard/allow-set.ts";
import { TacticalGuard } from "../src/guard/tactical-guard.ts";
import { isReadOnlyJob } from "../src/jobs/executors.ts";
import { JobRunner } from "../src/jobs/runner.ts";
import { Journal } from "../src/journal.ts";
import { createPatchGateClient, type PatchGateClient } from "../src/pg-client.ts";
import { heartbeatSchema, jobPayloadSchemas, rawFromPublicKey, tacticalPushSchema, TACTICAL_SERVICE_USERNAME, type GuardAllowEntry } from "../src/protocol.ts";
import { createTacticalClient, type TacticalClient } from "../src/tactical/client.ts";
import type { TacticalAuditLog } from "../src/tactical/types.ts";
import { silentLogger } from "../src/util/log.ts";
import { Semaphore } from "../src/util/semaphore.ts";
import { tempDir } from "./helpers/common.ts";
import { FakePatchGate } from "./helpers/fake-patchgate.ts";
import { FakeTactical, upd, type FakeAgent } from "./helpers/fake-tactical.ts";

/**
 * Real-time Tactical guard (protocol §8): approvals PatchGate did not authorise are reset within one guard round,
 * PatchGate's own (in-flight) approvals are never touched, nothing is reset while the allow-set is unknown, audit
 * entries are pushed with a cursor, Tactical reads are capped.
 */

const KEY = "TACTICAL-TEST-KEY-GUARD";
const SELF = "conn-guard";
const A1 = "agentAAAA1111";
const A2 = "agentBBBB2222";
const G = (n: number) => `${String(n).padStart(8, "0")}-0000-4000-8000-000000000000`;
const HOUR = 3_600_000;

let dir: string;
let cleanup: () => Promise<void>;
let pg: FakePatchGate;
let tactical: FakeTactical;
let tClient: TacticalClient;
let pgClient: PatchGateClient;
let journal: Journal;
let runner: JobRunner;
let guard: TacticalGuard;

async function openGuard(over: Partial<Parameters<typeof TacticalGuard.open>[0]> = {}): Promise<TacticalGuard> {
  return TacticalGuard.open({ tactical: tClient, pg: pgClient, stateFile: join(dir, "tactical-guard.json"), intervalMs: 30_000, maxAgentReadsPerTick: 25, log: silentLogger, ...over });
}

async function makeRunner(g: TacticalGuard): Promise<JobRunner> {
  const index = await CacheIndex.open(join(dir, "idx.json"), join(dir, "cache"));
  journal = await Journal.open(join(dir, "journal.jsonl"), { retentionDays: 30 });
  return new JobRunner({
    pg: pgClient,
    journal,
    connectorId: SELF,
    jobSigningPublicKey: pg.jobSigningPublicKey,
    deploySem: new Semaphore(2),
    otherSem: new Semaphore(2),
    log: silentLogger,
    postBackoff: { baseMs: 10, maxMs: 50 },
    deps: {
      tactical: tClient,
      index,
      downloader: new CacheDownloader({ pg: pgClient, index, root: join(dir, "cache"), maxPackageBytes: 1 << 20, minFreeBytes: 0, log: silentLogger }),
      cacheBaseUrl: "https://pgcache.bank.local/repo",
      installScriptTimeoutSec: 60,
      maxParallelCalls: 4,
      log: silentLogger,
      guard: g,
    },
  });
}

/** Restart with another guard (closes the old runner + journal first: Windows keeps open files locked). */
async function restart(over: Partial<Parameters<typeof TacticalGuard.open>[0]> = {}): Promise<void> {
  await guard.stop();
  await runner.shutdown(1000);
  await journal.close();
  guard = await openGuard(over);
  runner = await makeRunner(guard);
}

/** Deliver one signed job through the runner (verification, journal, result) and wait for it. */
async function deliver(type: Parameters<FakePatchGate["makeJob"]>[1], payload: unknown, over: Parameters<FakePatchGate["makeJob"]>[3] = {}) {
  const job = pg.makeJob(SELF, type, payload, over);
  pg.knownJobs.add(job.id);
  await runner.submit(job);
  await runner.idle();
  return pg.results.get(job.id);
}

async function sync(allow: GuardAllowEntry[] = [], auditCursor = 0, syncId = "sync-0001", part = 1, parts = 1) {
  return deliver("TACTICAL_GUARD_SYNC", { syncId, part, parts, allow, auditCursor });
}

const winUpdateCalls = () => tactical.calls.filter((c) => c.method === "GET" && /^\/winupdate\/[^/]+\/$/.test(c.path));
const puts = () => tactical.calls.filter((c) => c.method === "PUT" && c.path.startsWith("/winupdate/"));
const approved = (a: FakeAgent) => a.updates.filter((u) => u.action === "approve").map((u) => u.guid);

function auditLog(id: number, over: Partial<TacticalAuditLog> = {}): TacticalAuditLog {
  return {
    id,
    username: "tacticaladmin",
    agent: null,
    agent_id: null,
    entry_time: `2026-10-16T10:${String(id % 60).padStart(2, "0")}:00.000000+00:00`,
    action: "login",
    object_type: "user",
    message: "tacticaladmin logged in successfully",
    ip_address: "10.0.0.5",
    ...over,
  } as TacticalAuditLog;
}

beforeEach(async () => {
  ({ dir, cleanup } = await tempDir("pgc-guard-"));
  pg = new FakePatchGate();
  await pg.start();
  tactical = new FakeTactical({ apiKey: KEY });
  await tactical.start();
  const conn = generateKeyPairSync("ed25519");
  pg.connectors.set(SELF, { publicKey: rawFromPublicKey(conn.publicKey), tenantId: "t1" });
  pgClient = createPatchGateClient({ serverUrl: pg.url, connectorId: SELF, privateKey: conn.privateKey, timeoutMs: 5000 });
  tClient = createTacticalClient({ baseUrl: tactical.url, apiKey: KEY, timeoutMs: 5000 });
  guard = await openGuard();
  runner = await makeRunner(guard);
});
afterEach(async () => {
  await guard.stop();
  await runner.shutdown(1000);
  await journal.close();
  await pg.stop();
  await tactical.stop();
  await cleanup();
});

describe("protocol additions", () => {
  it("TACTICAL_GUARD_SYNC is strict, bounded and read-only; pushes and heartbeat guard status validate", () => {
    const ok = { syncId: "sync-0001", part: 1, parts: 1, allow: [{ agentId: A1, guids: [G(1)], until: new Date().toISOString() }], auditCursor: 0 };
    expect(jobPayloadSchemas.TACTICAL_GUARD_SYNC.safeParse(ok).success).toBe(true);
    expect(jobPayloadSchemas.TACTICAL_GUARD_SYNC.safeParse({ ...ok, part: 2 }).success).toBe(false); // part > parts
    expect(jobPayloadSchemas.TACTICAL_GUARD_SYNC.safeParse({ ...ok, path: "/accounts/" }).success).toBe(false);
    expect(jobPayloadSchemas.TACTICAL_GUARD_SYNC.safeParse({ ...ok, allow: [{ agentId: A1, guids: ["not-a-guid"], until: ok.allow[0]!.until }] }).success).toBe(false);
    expect(isReadOnlyJob("TACTICAL_GUARD_SYNC")).toBe(true);
    const ev = { id: 1, ts: "x", actor: "a", action: "login", objectType: "user", agentHostname: null, agentId: null, message: null, ip: null };
    expect(tacticalPushSchema.safeParse({ audit: { afterId: 0, events: Array.from({ length: 201 }, (_, i) => ({ ...ev, id: i + 1 })), cursor: 201 } }).success).toBe(false);
    expect(tacticalPushSchema.safeParse({ approvalResets: [], extra: 1 }).success).toBe(false);
    const hb = { version: "1", cache: { files: 0, bytes: 0 }, tactical: { reachable: true }, guard: guard.status() };
    expect(heartbeatSchema.safeParse(hb).success).toBe(true);
    expect(guard.status()).toMatchObject({ enabled: true, allowSetKnown: false, intervalSec: 30, resets: 0 });
  });
});

describe("allow-set", () => {
  it("classifies allowed / own-expired / foreign, merges per PC and forgets after the memory period", () => {
    const now = Date.now();
    const s = new AllowSet();
    s.add(A1, [G(1).toUpperCase()], now + HOUR);
    s.add(A1, [G(2)], now - HOUR); // older window: union, latest end kept
    s.add(A2, [G(3)], now - HOUR);
    expect(s.classify(A1, G(1), now)).toBe("allowed");
    expect(s.classify(A1, G(2), now)).toBe("allowed");
    expect(s.classify(A2, G(3), now)).toBe("own-expired");
    expect(s.classify(A2, G(4), now)).toBe("foreign");
    expect(s.inFlight(A1, now)).toBe(true);
    expect(s.inFlight(A2, now)).toBe(false);
    expect(s.prune(now + OWN_APPROVAL_MEMORY_MS)).toBe(1); // A2 forgotten, A1 still within memory
    expect(AllowSet.fromEntries(s.toEntries()).classify(A1, G(1), now)).toBe("allowed");
  });
});

describe("approval guard", () => {
  it("resets nothing while the allow-set is unknown (after a start)", async () => {
    const a = tactical.addAgent({ agent_id: A1, updates: [upd(G(1), { action: "approve", kb: "KB5000001" })] });
    const r = await guard.tick();
    expect(r.skipped).toBe("allow-set unknown");
    expect(approved(a)).toEqual([G(1)]);
    expect(tactical.calls).toEqual([]);
    expect(pg.tacticalPushes).toEqual([]);
  });

  it("resets a foreign approval within one guard round and reports it (signed push)", async () => {
    const a = tactical.addAgent({ agent_id: A1, hostname: "DESKTOP-Q6U5I2R", updates: [upd(G(1), { action: "approve", kb: "KB5000001", title: "2026-10 Cumulative Update" }), upd(G(2))] });
    expect(await sync()).toEqual({ ok: true, result: { allowEntries: 0, known: true } });
    const r = await guard.tick();
    expect(r).toMatchObject({ agentsRead: 1, resets: 1, reported: 1, pushes: 1 });
    expect(approved(a)).toEqual([]);
    expect(pg.tacticalPushes).toHaveLength(1);
    expect(pg.tacticalPushes[0]!.approvalResets).toEqual([
      expect.objectContaining({ agentId: A1, hostname: "DESKTOP-Q6U5I2R", guid: G(1), kb: "KB5000001", reset: true, error: null }),
    ]);
    expect(guard.pendingReports).toEqual([]);
    expect(guard.status()).toMatchObject({ allowSetKnown: true, resets: 1, error: null });
    // nothing left: the next round reads no PC's updates and pushes nothing
    tactical.calls.length = 0;
    expect(await guard.tick()).toMatchObject({ agentsRead: 0, pushes: 0 });
    expect(winUpdateCalls()).toEqual([]);
  });

  it("never touches PatchGate-authorised approvals (signed DEPLOY_WINDOWS, or the synced allow-set)", async () => {
    const a1 = tactical.addAgent({ agent_id: A1, updates: [upd(G(1)), upd(G(9), { action: "approve" })] });
    const a2 = tactical.addAgent({ agent_id: A2, updates: [upd(G(3), { action: "approve" })] });
    await sync([{ agentId: A2, guids: [G(3)], until: new Date(Date.now() + HOUR).toISOString() }]);
    // PatchGate deploys G(1) on A1: the executor approves it (and itself withdraws the foreign G(9))
    const res = await deliver("DEPLOY_WINDOWS", { agentId: A1, guids: [G(1)], rebootPolicy: "NEVER" });
    expect(res).toMatchObject({ ok: true, result: { outcome: "INSTALL_STARTED" } });
    expect(approved(a1)).toEqual([G(1)]);
    a1.updates.push(upd(G(5), { action: "approve", kb: "KB5000005" })); // a human approves one more on the same PC
    tactical.calls.length = 0;
    const r = await guard.tick();
    expect(r.resets).toBe(1);
    expect(approved(a1)).toEqual([G(1)]); // in-flight approval untouched, the foreign one reset
    expect(approved(a2)).toEqual([G(3)]);
    expect(puts()).toHaveLength(1);
  });

  it("reports a reset a Tactical patch policy undoes at once (not counted as reset)", async () => {
    const a = tactical.addAgent({ agent_id: A1, updates: [upd(G(1), { action: "approve" })] });
    tactical.policyApproved.add(a.updates[0]!.id);
    await sync();
    expect(await guard.tick()).toMatchObject({ resets: 0, reported: 1 });
    expect(pg.tacticalPushes[0]!.approvalResets![0]).toMatchObject({ reset: false, error: expect.stringMatching(/patch policy/) });
  });

  it("leaves a PC alone while a PatchGate job changes its approvals", async () => {
    const a = tactical.addAgent({ agent_id: A1, updates: [upd(G(1), { action: "approve" })] });
    await sync();
    let release!: () => void;
    const busy = guard.busyAgent(A1, () => new Promise<void>((r) => (release = r)));
    expect(await guard.tick()).toMatchObject({ agentsRead: 0, resets: 0 });
    expect(approved(a)).toEqual([G(1)]);
    release();
    await busy;
    expect(await guard.tick()).toMatchObject({ resets: 1 });
  });

  it("withdraws leftovers of an ended PatchGate window quietly (no alert)", async () => {
    const a = tactical.addAgent({ agent_id: A1, updates: [upd(G(1), { action: "approve" })] });
    await sync([{ agentId: A1, guids: [G(1)], until: new Date(Date.now() - HOUR).toISOString() }]);
    const r = await guard.tick();
    expect(r).toMatchObject({ resets: 0, reported: 0, pushes: 0 });
    expect(approved(a)).toEqual([]);
    expect(pg.tacticalPushes).toEqual([]);
  });

  it("arms only once every part of a sync arrived", async () => {
    tactical.addAgent({ agent_id: A1, updates: [upd(G(1), { action: "approve" })] });
    const part1 = await sync([{ agentId: A1, guids: [G(1)], until: new Date(Date.now() + HOUR).toISOString() }], 0, "sync-parts", 1, 2);
    expect(part1).toMatchObject({ ok: true, result: { known: false } });
    expect((await guard.tick()).skipped).toBe("allow-set unknown");
    expect(await sync([], 0, "sync-parts", 2, 2)).toMatchObject({ ok: true, result: { allowEntries: 1, known: true } });
    expect(await guard.tick()).toMatchObject({ resets: 0 }); // part 1 allowed it
  });

  it("caps per-PC update reads per round and only reads PCs with pending approvals", async () => {
    for (let i = 0; i < 5; i++) tactical.addAgent({ agent_id: `agentFLAG000${i}`, updates: [upd(G(10 + i), { action: "approve" })] });
    for (let i = 0; i < 20; i++) tactical.addAgent({ agent_id: `agentCLEAN00${String(i).padStart(2, "0")}`, updates: [upd(G(100 + i))] });
    await restart({ maxAgentReadsPerTick: 2 });
    await sync();
    tactical.calls.length = 0;
    const readPcs = () => new Set(winUpdateCalls().map((c) => c.path)).size;
    expect(await guard.tick()).toMatchObject({ agentsRead: 2, resets: 2 });
    expect(readPcs()).toBe(2);
    expect(winUpdateCalls()).toHaveLength(4); // + one verification read per PC where something was reset
    expect(winUpdateCalls().every((c) => c.path.includes("FLAG"))).toBe(true);
    expect(tactical.calls.filter((c) => c.path === "/agents/")).toHaveLength(1);
    await guard.tick();
    await guard.tick();
    expect(readPcs()).toBe(5); // the last round had only one flagged PC left
    // An older Tactical without has_patches_pending: round-robin over every PC, still capped
    tactical.patchFlag = false;
    tactical.calls.length = 0;
    await guard.tick();
    expect(winUpdateCalls()).toHaveLength(2);
  });

  it("keeps unsent reports across a PatchGate outage and a restart; the allow-set must be re-sent", async () => {
    tactical.addAgent({ agent_id: A1, updates: [upd(G(1), { action: "approve" })] });
    await sync();
    pg.pushStatusQueue.push(503);
    const r = await guard.tick();
    expect(r).toMatchObject({ resets: 1, pushes: 0 });
    expect(guard.status().error).toMatch(/503/);
    expect(guard.pendingReports).toHaveLength(1);
    await guard.stop();
    const state = JSON.parse(await readFile(join(dir, "tactical-guard.json"), "utf8")) as { outbox: unknown[] };
    expect(state.outbox).toHaveLength(1);
    await restart();
    expect(guard.allowSetKnown).toBe(false); // restart: unknown until PatchGate's signed sync
    expect(guard.pendingReports).toHaveLength(1);
    await sync();
    expect(await guard.tick()).toMatchObject({ pushes: 1 });
    expect(pg.tacticalPushes[0]!.approvalResets).toHaveLength(1);
  });

  it("reports a reset Tactical refuses, but not again every round", async () => {
    const a = tactical.addAgent({ agent_id: A1, updates: [upd(G(1), { action: "approve" })] });
    await sync();
    tactical.putStatus = 500;
    await guard.tick();
    await guard.tick();
    const resets = pg.tacticalPushes.flatMap((p) => p.approvalResets ?? []);
    expect(resets).toHaveLength(1);
    expect(resets[0]).toMatchObject({ reset: false, error: expect.stringMatching(/500/) });
    expect(approved(a)).toEqual([G(1)]);
  });
});

describe("audit-log stream", () => {
  it("pushes out-of-band entries from the synced cursor, advances it, and pages a backlog in bounded batches", async () => {
    tactical.auditLogs.push(auditLog(1), auditLog(2), auditLog(3, { username: TACTICAL_SERVICE_USERNAME, action: "execute_script", object_type: "agent" }), auditLog(4));
    await sync([], 1);
    expect(guard.cursor).toBe(1);
    const r = await guard.tick();
    expect(r).toMatchObject({ pushes: 1, auditEvents: 2 });
    expect(pg.tacticalPushes[0]!.audit).toMatchObject({ afterId: 1, cursor: 4 });
    expect(pg.tacticalPushes[0]!.audit!.events.map((e) => e.id)).toEqual([2, 4]);
    expect(guard.cursor).toBe(4);
    // only the service account's work afterwards: cursor moves, nothing is pushed
    tactical.auditLogs.push(auditLog(5, { username: TACTICAL_SERVICE_USERNAME, action: "execute_script", object_type: "agent" }));
    expect(await guard.tick()).toMatchObject({ pushes: 0 });
    expect(guard.cursor).toBe(5);
    // a backlog of 250 human entries: 200 + 50, cursor at the end
    for (let i = 6; i < 256; i++) tactical.auditLogs.push(auditLog(i));
    expect(await guard.tick()).toMatchObject({ pushes: 2, auditEvents: 250 });
    expect(pg.tacticalPushes.slice(1).map((p) => p.audit!.events.length)).toEqual([200, 50]);
    expect(guard.cursor).toBe(255);
  });

  it("does not advance the cursor when PatchGate is unreachable; drops a batch PatchGate refuses for good", async () => {
    tactical.auditLogs.push(auditLog(1), auditLog(2));
    await sync([], 1);
    pg.pushStatusQueue.push(503);
    await guard.tick();
    expect(guard.cursor).toBe(1);
    await guard.tick();
    expect(guard.cursor).toBe(2);
    expect(pg.tacticalPushes).toHaveLength(1);
    tactical.auditLogs.push(auditLog(3));
    pg.pushStatusQueue.push(422);
    await guard.tick();
    expect(guard.cursor).toBe(3); // never loops on a refused batch
  });

  it("reports a purged Tactical audit log (newest id below the cursor)", async () => {
    tactical.auditLogs.push(auditLog(1));
    await sync([], 40);
    await guard.tick();
    expect(pg.tacticalPushes[0]!.audit).toMatchObject({ afterId: 40, reset: true, cursor: 1 });
  });

  it("guard off (interval 0): sync acknowledged, nothing armed, no rounds", async () => {
    await restart({ intervalMs: 0 });
    tactical.addAgent({ agent_id: A1, updates: [upd(G(1), { action: "approve" })] });
    expect(await sync()).toEqual({ ok: true, result: { allowEntries: 0, known: false } });
    expect((await guard.tick()).skipped).toBe("disabled");
    expect(tactical.calls).toEqual([]);
  });
});
