/**
 * Signed job queue: signing + byte-identical re-delivery, concurrent long polls, idempotent results,
 * retries as new jobs, expiry.
 */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { TENANT_A, TENANT_B, configureTestEnv, resetDb } from "./helpers";
import { enrollBody, makeConnectorKey, sessionUserOf } from "./connector-helpers";

const repoDir = mkdtempSync(join(tmpdir(), "pg-conn-jobs-"));
configureTestEnv({ REPO_DIR: repoDir, LOG_LEVEL: "error" });
const { prisma } = await import("@/lib/db");
const { withTenant } = await import("@/lib/tenancy");
const { createEnrollmentCode } = await import("@/lib/connector/admin");
const { redeemEnrollment } = await import("@/lib/connector/enroll");
const { enqueueJob, claimJobs, pollJobs, expireJobs } = await import("@/lib/connector/queue");
const { acceptResult, processJobResult, processPendingResults } = await import("@/lib/connector/results");
const { REDELIVERY_LEASE_MS } = await import("@/lib/connector/policy");
const { verifyJob, canonicalJson } = await import("@/lib/connector/protocol");

beforeEach(() => resetDb(prisma));
afterAll(async () => {
  await prisma.$disconnect();
  rmSync(repoDir, { recursive: true, force: true });
});

interface Conn {
  id: string;
  tenantId: string;
  name: string;
  maxConcurrentInstalls: number;
  bandwidthLimitMbps: number | null;
  jobKey: string;
}

async function connector(tenantId = TENANT_A, name = "HQ"): Promise<Conn> {
  const admin = sessionUserOf(await prisma.user.upsert({ where: { upn: "admin@pg" }, update: {}, create: { upn: "admin@pg", name: "A", role: "ADMIN" } }));
  const { code } = await createEnrollmentCode(admin, { tenantId, name });
  const r = await redeemEnrollment(enrollBody(code, makeConnectorKey()));
  return { id: r.connectorId, tenantId, name, maxConcurrentInstalls: 50, bandwidthLimitMbps: null, jobKey: r.jobSigningPublicKey };
}

const hour = () => new Date(Date.now() + 60 * 60_000);
const AGENT = "agentJOBS0001";

async function enqueue(c: Conn, n = 1) {
  const ids: string[] = [];
  for (let i = 0; i < n; i++) {
    const j = await withTenant(c.tenantId, (tx) => enqueueJob(tx, { tenantId: c.tenantId, connectorId: c.id, type: "SCAN", payload: { agentIds: [AGENT] }, expiresAt: hour() }));
    ids.push(j.id);
  }
  return ids;
}

describe("signing and delivery", () => {
  it("delivers jobs the connector verifies, and re-delivers them byte-identically after the lease", async () => {
    const c = await connector();
    const [id] = await enqueue(c);
    const first = await claimJobs(c.tenantId, c.id);
    expect(first.map((j) => j.id)).toEqual([id]);
    expect(Object.keys(first[0]).sort()).toEqual(["connectorId", "expiresAt", "id", "notBefore", "payload", "signature", "tenantId", "type", "v"]);
    expect(verifyJob(first[0], c.jobKey, c.id, Date.now())).toMatchObject({ ok: true, type: "SCAN" });
    expect(verifyJob(first[0], c.jobKey, "another-connector", Date.now())).toMatchObject({ ok: false, reason: "job is for another connector" });
    expect(verifyJob({ ...first[0], payload: { agentIds: ["agentEVIL0001"] } }, c.jobKey, c.id, Date.now())).toMatchObject({ ok: false, reason: "bad job signature" });

    expect(await claimJobs(c.tenantId, c.id)).toEqual([]); // leased
    const again = await claimJobs(c.tenantId, c.id, new Date(Date.now() + REDELIVERY_LEASE_MS + 1000));
    expect(canonicalJson(again[0])).toBe(canonicalJson(first[0]));
  });

  it("never delivers another connector's (or another bank's) jobs and holds future jobs back", async () => {
    const a = await connector(TENANT_A, "HQ");
    const b = await connector(TENANT_B, "HQ");
    await enqueue(a);
    await withTenant(a.tenantId, (tx) =>
      enqueueJob(tx, { tenantId: a.tenantId, connectorId: a.id, type: "SYNC_AGENTS", payload: {}, notBefore: new Date(Date.now() + 10 * 60_000), expiresAt: hour() }),
    );
    expect(await claimJobs(b.tenantId, b.id)).toEqual([]);
    expect(await claimJobs(a.tenantId, b.id)).toEqual([]); // wrong pairing sees nothing either
    expect((await claimJobs(a.tenantId, a.id)).map((j) => j.type)).toEqual(["SCAN"]);
  });

  it("two concurrent pollers never receive the same job", async () => {
    const c = await connector();
    const ids = await enqueue(c, 30);
    const [p1, p2, p3] = await Promise.all([claimJobs(c.tenantId, c.id), claimJobs(c.tenantId, c.id), claimJobs(c.tenantId, c.id)]);
    const got = [...p1, ...p2, ...p3].map((j) => j.id);
    expect(new Set(got).size).toBe(got.length);
    expect(got.length).toBe(30);
    expect([...got].sort()).toEqual([...ids].sort());
    expect(Math.max(p1.length, p2.length, p3.length)).toBeLessThanOrEqual(20);
  });

  it("long poll returns as soon as a job arrives", async () => {
    const c = await connector();
    const started = Date.now();
    const poll = pollJobs(c.tenantId, c.id, 10);
    setTimeout(() => void enqueue(c), 1500);
    const jobs = await poll;
    expect(jobs).toHaveLength(1);
    expect(Date.now() - started).toBeLessThan(8000);
    // and an empty poll waits about `wait` seconds
    const t0 = Date.now();
    expect(await pollJobs(c.tenantId, c.id, 2)).toEqual([]);
    expect(Date.now() - t0).toBeGreaterThanOrEqual(1500);
  });
});

describe("results", () => {
  it("first result wins (409 after), unknown / foreign jobs are 404, results are applied once", async () => {
    const a = await connector(TENANT_A, "HQ");
    const b = await connector(TENANT_B, "HQ");
    const ep = await prisma.endpoint.create({ data: { tenantId: TENANT_A, tacticalAgentId: AGENT, hostname: "PC1", connectorId: a.id } });
    const [id] = await enqueue(a);
    await claimJobs(a.tenantId, a.id);

    await expect(acceptResult(b, id, { ok: true, result: { requested: [AGENT], failed: [] } })).rejects.toMatchObject({ status: 404 });
    await expect(acceptResult(a, "job_unknown", { ok: true, result: {} })).rejects.toMatchObject({ status: 404 });
    await expect(acceptResult(a, id, { nope: 1 })).rejects.toMatchObject({ status: 400 });

    const results = await Promise.allSettled([
      acceptResult(a, id, { ok: true, result: { requested: [AGENT], failed: [] } }),
      acceptResult(a, id, { ok: true, result: { requested: [AGENT], failed: [] } }),
    ]);
    expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
    expect(results.find((r) => r.status === "rejected")).toMatchObject({ reason: { status: 409 } });

    expect(await processJobResult(a.tenantId, id)).toBe("applied");
    expect(await processJobResult(a.tenantId, id)).toBe("skipped");
    expect((await prisma.endpoint.findUniqueOrThrow({ where: { id: ep.id } })).lastScanRequestedAt).not.toBeNull();
    expect(await prisma.connectorJob.findUniqueOrThrow({ where: { id } })).toMatchObject({ status: "SUCCEEDED", processAttempts: 1 });
  });

  it("an invalid result is stored as a permanent failure (422) and not retried", async () => {
    const c = await connector();
    const [id] = await enqueue(c);
    await expect(acceptResult(c, id, { ok: true, result: { requested: "nope" } })).rejects.toMatchObject({ status: 422 });
    expect(await prisma.connectorJob.findUniqueOrThrow({ where: { id } })).toMatchObject({ status: "FAILED", error: expect.stringMatching(/invalid SCAN result/) });
    await expect(acceptResult(c, id, { ok: true, result: { requested: [], failed: [] } })).rejects.toMatchObject({ status: 409 });
    expect(await processPendingResults()).toMatchObject({ applied: 1 });
    expect(await prisma.connectorJob.count()).toBe(1); // no retry job
  });

  it("a retryable failure becomes a NEW job (new id, next generation, later notBefore); permanent ones do not", async () => {
    const c = await connector();
    const [id] = await enqueue(c);
    await acceptResult(c, id, { ok: false, error: "Tactical unreachable", retryable: true });
    await processJobResult(c.tenantId, id);
    const retry = await prisma.connectorJob.findFirstOrThrow({ where: { id: { not: id } } });
    expect(retry).toMatchObject({ type: "SCAN", status: "QUEUED", attempts: 1, payload: { agentIds: [AGENT] } });
    expect(retry.notBefore.getTime()).toBeGreaterThan(Date.now());

    await acceptResult(c, retry.id, { ok: false, error: "bad agent", retryable: false });
    await processJobResult(c.tenantId, retry.id);
    expect(await prisma.connectorJob.count()).toBe(2);
  });

  it("expiry: unanswered jobs past expiresAt become EXPIRED; a late result is still accepted and applied", async () => {
    const c = await connector();
    const [id] = await enqueue(c);
    await claimJobs(c.tenantId, c.id);
    const expired = await expireJobs(new Date(Date.now() + 2 * 60 * 60_000));
    expect(expired).toEqual([expect.objectContaining({ id, delivered: true, type: "SCAN" })]);
    await acceptResult(c, id, { ok: true, result: { requested: [], failed: [] } });
    expect(await processJobResult(c.tenantId, id)).toBe("applied");
  });
});
