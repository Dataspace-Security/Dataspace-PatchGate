/**
 * Deployments through site connectors: cache-before-deploy, LAN caps (maxConcurrentInstalls), staggering,
 * window expiry, ring stop, confirmation via COLLECT, Windows (DEPLOY_WINDOWS) path, legacy stand-down.
 */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { TacticalClient } from "@/lib/tactical/client";
import { TENANT_A, configureTestEnv, resetDb } from "./helpers";
import { enrollBody, makeConnectorKey, sessionUserOf, writeRepoFile } from "./connector-helpers";

const repoDir = mkdtempSync(join(tmpdir(), "pg-conn-deploy-"));
configureTestEnv({ REPO_DIR: repoDir, LOG_LEVEL: "error" });
const { prisma } = await import("@/lib/db");
const { createEnrollmentCode } = await import("@/lib/connector/admin");
const { redeemEnrollment } = await import("@/lib/connector/enroll");
const { claimJobs, expireJobs } = await import("@/lib/connector/queue");
const { acceptResult, processJobResult } = await import("@/lib/connector/results");
const { STAGGER_PER_SLOT_MS } = await import("@/lib/connector/policy");
const { createChangeRequest, applyAction } = await import("@/lib/approvals/service");
const { startDeployment } = await import("@/lib/deploy/start");
const { produceConnectorDeployments, pumpConnector, onJobsExpired } = await import("@/lib/deploy/connector-deploy");
const { confirmConnectorDeployments } = await import("@/lib/deploy/connector-confirm");
const { finaliseChangeRequests, processQueue } = await import("@/lib/deploy/worker");
const { verifyAuditLog } = await import("@/lib/audit/service");

beforeEach(() => resetDb(prisma));
afterAll(async () => {
  await prisma.$disconnect();
  rmSync(repoDir, { recursive: true, force: true });
});

const GUID = "44444444-4444-4444-4444-444444444444";

async function connector(maxConcurrentInstalls: number) {
  const admin = sessionUserOf(await prisma.user.upsert({ where: { upn: "admin@pg" }, update: {}, create: { upn: "admin@pg", name: "A", role: "ADMIN" } }));
  const { code } = await createEnrollmentCode(admin, { tenantId: TENANT_A, name: "HQ" });
  const r = await redeemEnrollment(enrollBody(code, makeConnectorKey()));
  await prisma.connector.update({ where: { id: r.connectorId }, data: { maxConcurrentInstalls } });
  return { id: r.connectorId, tenantId: TENANT_A, name: "HQ", maxConcurrentInstalls, bandwidthLimitMbps: null };
}
type Conn = Awaited<ReturnType<typeof connector>>;

async function sevenZip() {
  const file = writeRepoFile(repoDir, "pkgs/7zip/24.08/7z2408-x64.msi", "pretend MSI bytes for 7-Zip 24.08");
  const app = await prisma.app.create({ data: { wingetId: "7zip.7zip", displayName: "7-Zip", inventoryMatch: "^7-Zip", expectedPublisher: "O=Igor Pavlov", allowedDomains: [] } });
  const v = await prisma.appVersion.create({
    data: {
      appId: app.id, version: "24.08", installerUrl: "https://github.com/x.msi", sha256: file.sha256, silentArgs: "", verification: "VERIFIED",
      repoPath: file.repoPath, availableAt: new Date(Date.now() - 1000), signerOrg: "Igor Pavlov",
    },
  });
  const patch = await prisma.patch.create({ data: { kind: "THIRD_PARTY", externalId: "7zip.7zip@24.08", title: "7-Zip 24.08", appVersionId: v.id } });
  await prisma.tenantApp.create({ data: { tenantId: TENANT_A, appId: app.id, enabledBy: "admin@pg" } });
  return { patch, file };
}

/** Approved + started change request for `n` PCs on connector `c` (window: every hour for 2 h → always open). */
async function deploying(c: Conn, n: number, patchIds: string[]) {
  const maker = sessionUserOf(await prisma.user.create({ data: { upn: `op${Math.random()}@pg`, name: "Op", role: "ADMIN" } }));
  const checker = sessionUserOf(await prisma.user.create({ data: { upn: `ap${Math.random()}@a`, name: "Ap", role: "ADMIN", tenantId: TENANT_A } }));
  const ring = await prisma.ring.create({ data: { tenantId: TENANT_A, name: "R0", wsusGroup: "R0", order: 0 } });
  const window = await prisma.maintenanceWindow.create({ data: { tenantId: TENANT_A, ringId: ring.id, name: "Hourly", cron: "0 * * * *", durationMin: 120, timezone: "UTC" } });
  await prisma.endpoint.createMany({
    data: Array.from({ length: n }, (_, i) => ({ tenantId: TENANT_A, tacticalAgentId: `agentDEPL${String(i).padStart(4, "0")}`, hostname: `PC${i}`, ringId: ring.id, connectorId: c.id, goarch: "amd64" })),
  });
  const cr = await createChangeRequest(maker, TENANT_A, { title: "Patch Tuesday", ringId: ring.id, windowId: window.id, patchIds });
  await applyAction(maker, TENANT_A, cr.id, "submit");
  await applyAction(checker, TENANT_A, cr.id, "approve");
  await startDeployment(checker, TENANT_A, cr.id);
  return { crId: cr.id, ringId: ring.id };
}

async function post(c: Conn, jobId: string, result: unknown) {
  await acceptResult(c, jobId, result);
  expect(await processJobResult(c.tenantId, jobId)).toBe("applied");
}

const installJobs = (where: object = {}) =>
  prisma.connectorJob.findMany({ where: { type: { in: ["DEPLOY_PACKAGE", "DEPLOY_WINDOWS", "WU_INSTALL"] }, ...where }, orderBy: { createdAt: "asc" } });
const inFlight = () => prisma.connectorJob.count({ where: { type: { in: ["DEPLOY_PACKAGE", "DEPLOY_WINDOWS", "WU_INSTALL"] }, status: { in: ["QUEUED", "DELIVERED"] } } });

async function cacheOk(c: Conn) {
  const cache = await prisma.connectorJob.findFirstOrThrow({ where: { type: "CACHE_PACKAGE", status: { in: ["QUEUED", "DELIVERED"] } } });
  const pkg = (cache.payload as { package: { sha256: string; size: number; repoPath: string } }).package;
  await post(c, cache.id, { ok: true, result: { sha256: pkg.sha256, size: pkg.size, cachedPath: pkg.repoPath } });
}

describe("LAN protection", () => {
  it("caches once per site, then never has more than maxConcurrentInstalls installs in flight; releases more as results arrive", async () => {
    const c = await connector(3);
    const { patch, file } = await sevenZip();
    await deploying(c, 10, [patch.id]);

    // 1st pass: the package is not at the site yet → exactly one CACHE_PACKAGE, no installs, PCs stay QUEUED
    await produceConnectorDeployments();
    await produceConnectorDeployments();
    const caches = await prisma.connectorJob.findMany({ where: { type: "CACHE_PACKAGE" } });
    expect(caches).toHaveLength(1);
    expect(caches[0].payload).toMatchObject({ package: { kind: "msi", sha256: file.sha256, size: file.size, repoPath: file.repoPath, publisher: "O=Igor Pavlov" } });
    expect(await inFlight()).toBe(0);
    expect(await prisma.deployment.count({ where: { status: "QUEUED" } })).toBe(10);

    // cached → the pump releases exactly 3 installs, staggered inside the window, expiring at the window end
    const before = Date.now();
    await cacheOk(c);
    const jobs = await installJobs();
    expect(jobs).toHaveLength(3);
    expect(await prisma.deployment.count({ where: { status: "SENDING" } })).toBe(3);
    const windowEnd = new Date(Math.floor(Date.now() / 3_600_000) * 3_600_000 + 2 * 3_600_000);
    for (const j of jobs) {
      expect(j.expiresAt.getTime()).toBe(windowEnd.getTime());
      expect(j.notBefore.getTime()).toBeGreaterThanOrEqual(before - 1000);
      expect(j.notBefore.getTime()).toBeLessThanOrEqual(Date.now() + 3 * STAGGER_PER_SLOT_MS);
      expect(j.payload).toMatchObject({ agentId: expect.stringMatching(/^agentDEPL/), package: { sha256: file.sha256 } });
    }

    // repeated / concurrent pumps (two web instances) never exceed the cap
    await Promise.all([pumpConnector(c.tenantId, c.id), pumpConnector(c.tenantId, c.id), produceConnectorDeployments()]);
    expect(await inFlight()).toBe(3);

    // one install finishes → its deployment is SENT (awaiting inventory) and the next PC is released
    await prisma.connectorJob.updateMany({ data: { notBefore: new Date(Date.now() - 1000) } });
    const [first] = await claimJobs(c.tenantId, c.id);
    await post(c, first.id, { ok: true, result: { outcome: "INSTALLED", output: "PATCHGATE_RESULT=OK" } });
    expect(await prisma.deployment.count({ where: { status: "SENT" } })).toBe(1);
    expect(await inFlight()).toBe(3);
    expect(await installJobs()).toHaveLength(4);
    expect(await prisma.connectorJob.count({ where: { type: "CACHE_PACKAGE" } })).toBe(1); // still one download for the site
  });

  it("confirms via COLLECT inventory, then the change request completes", async () => {
    const c = await connector(5);
    const { patch } = await sevenZip();
    const { crId } = await deploying(c, 1, [patch.id]);
    await produceConnectorDeployments();
    await cacheOk(c);
    const [install] = await installJobs();
    await post(c, install.id, { ok: true, result: { outcome: "INSTALLED" } });
    const d = await prisma.deployment.findFirstOrThrow();
    expect(d.status).toBe("SENT");

    // confirmation asks the site for fresh inventory (one COLLECT batch), never Tactical directly
    const r = await confirmConnectorDeployments();
    expect(r.collectJobs).toBe(1);
    expect((await confirmConnectorDeployments()).collectJobs).toBe(0); // not asked twice
    const collect = await prisma.connectorJob.findFirstOrThrow({ where: { type: "COLLECT" } });
    await claimJobs(c.tenantId, c.id);
    await post(c, collect.id, {
      ok: true,
      result: { agents: [{ agentId: "agentDEPL0000", updates: [], software: [{ name: "7-Zip 24.08 (x64)", version: "24.08" }], agent: { version: "2.10.0" } }] },
    });
    expect((await prisma.deployment.findFirstOrThrow()).status).toBe("SUCCEEDED");
    await finaliseChangeRequests();
    expect((await prisma.changeRequest.findUniqueOrThrow({ where: { id: crId } })).status).toBe("COMPLETED");
    expect(await verifyAuditLog(TENANT_A)).toMatchObject({ valid: true });
  });

  it("stops the ring when more than 20 % of ≥ 10 results failed: not-started work is FAILED with a note and audited", async () => {
    const c = await connector(12);
    const { patch } = await sevenZip();
    const { crId } = await deploying(c, 20, [patch.id]);
    await produceConnectorDeployments();
    await cacheOk(c);
    const jobs = await installJobs();
    expect(jobs).toHaveLength(12);
    // 7 already confirmed, one install is running on a PC right now
    const done = jobs.slice(3, 10).map((j) => j.deploymentId!);
    await prisma.deployment.updateMany({ where: { id: { in: done } }, data: { status: "SUCCEEDED", finishedAt: new Date() } });
    await prisma.connectorJob.update({ where: { id: jobs[11].id }, data: { status: "DELIVERED", deliveredAt: new Date() } });

    for (const j of jobs.slice(0, 3)) await post(c, j.id, { ok: false, error: "PATCHGATE_RESULT=FAIL:msiexec 1603", retryable: false });

    const counts = Object.fromEntries((await prisma.deployment.groupBy({ by: ["status"], _count: { _all: true } })).map((g) => [g.status, g._count._all]));
    expect(counts).toEqual({ SUCCEEDED: 7, FAILED: 3 + 1 + 8, SENDING: 1 }); // the running one finishes on its PC
    const stopped = await prisma.deployment.findFirstOrThrow({ where: { status: "FAILED", note: { not: null } } });
    expect(stopped.note).toMatch(/ring stopped: 3 of 10 installs failed \(30 %\)/);
    expect(await prisma.connectorJob.count({ where: { status: "CANCELLED" } })).toBeGreaterThan(0);
    expect(await prisma.auditEvent.count({ where: { action: "change_request.ring_stopped", entityId: crId, tenantId: TENANT_A } })).toBe(1);
    // nothing new is released for a stopped ring
    await produceConnectorDeployments();
    expect(await inFlight()).toBe(1);
  });

  it("window end: an undelivered install goes back to the queue, a delivered one is confirmed via inventory", async () => {
    const c = await connector(2);
    const { patch } = await sevenZip();
    await deploying(c, 2, [patch.id]);
    await produceConnectorDeployments();
    await cacheOk(c);
    const [a, b] = await installJobs();
    await prisma.connectorJob.update({ where: { id: a.id }, data: { status: "DELIVERED", deliveredAt: new Date() } });
    const expired = await expireJobs(new Date(a.expiresAt.getTime() + 1000));
    expect(expired.map((e) => e.id).sort()).toEqual([a.id, b.id].sort());
    await onJobsExpired(expired);
    expect((await prisma.deployment.findUniqueOrThrow({ where: { id: a.deploymentId! } })).status).toBe("SENT");
    expect(await prisma.deployment.findUniqueOrThrow({ where: { id: b.deploymentId! } })).toMatchObject({ status: "QUEUED", note: expect.stringMatching(/re-queued/) });
  });

  it("PCs no active connector manages fail after a grace period instead of blocking the change request", async () => {
    const c = await connector(5);
    const { patch } = await sevenZip();
    const { crId } = await deploying(c, 2, [patch.id]);
    const [gone, kept] = await prisma.endpoint.findMany({ orderBy: { tacticalAgentId: "asc" } });
    await prisma.endpoint.update({ where: { id: gone.id }, data: { connectorId: null, lastSeenAt: new Date(Date.now() - 3 * 60 * 60_000) } });
    await prisma.endpoint.update({ where: { id: kept.id }, data: { lastSeenAt: new Date() } });
    await produceConnectorDeployments();
    expect(await prisma.deployment.findFirstOrThrow({ where: { endpointId: gone.id } })).toMatchObject({ status: "FAILED", error: expect.stringMatching(/no active site connector/) });
    expect((await prisma.deployment.findFirstOrThrow({ where: { endpointId: kept.id } })).status).toBe("QUEUED");
    expect((await prisma.changeRequest.findUniqueOrThrow({ where: { id: crId } })).status).toBe("DEPLOYING");
  });

  it("an offline connector gets no new work", async () => {
    const c = await connector(5);
    const { patch } = await sevenZip();
    await deploying(c, 3, [patch.id]);
    await prisma.connector.update({ where: { id: c.id }, data: { lastSeenAt: new Date(Date.now() - 11 * 60_000) } });
    await produceConnectorDeployments();
    expect(await prisma.connectorJob.count({ where: { type: { not: "SYNC_AGENTS" } } })).toBe(0);
  });
});

describe("Windows updates (legacy WSUS banks: DEPLOY_WINDOWS)", () => {
  beforeEach(() => prisma.tenant.update({ where: { id: TENANT_A }, data: { windowsUpdateSource: "WSUS" } }));

  it("approves exactly the change request's GUIDs, confirms from COLLECT, and withdraws approvals on failure", async () => {
    const c = await connector(5);
    const win = await prisma.patch.create({ data: { kind: "WINDOWS", externalId: GUID, kb: "KB5000001", title: "KB5000001", severity: "CRITICAL" } });
    await deploying(c, 2, [win.id]);
    await produceConnectorDeployments();
    const jobs = await installJobs();
    expect(jobs).toHaveLength(2); // nothing to cache for Windows updates
    expect(jobs[0].payload).toMatchObject({ guids: [GUID], rebootPolicy: "IF_REQUIRED" });

    await post(c, jobs[0].id, { ok: true, result: { outcome: "INSTALL_STARTED", approved: [GUID] } });
    expect(await prisma.deployment.findUniqueOrThrow({ where: { id: jobs[0].deploymentId! } })).toMatchObject({ status: "SENT", targetGuids: [GUID] });

    await post(c, jobs[1].id, { ok: false, error: "Tactical approval state mismatch", retryable: false });
    expect((await prisma.deployment.findUniqueOrThrow({ where: { id: jobs[1].deploymentId! } })).status).toBe("FAILED");
    expect(await prisma.connectorJob.findFirstOrThrow({ where: { type: "RESET_APPROVALS" } })).toMatchObject({ payload: { agentId: expect.stringMatching(/^agentDEPL/) } });
  });

  it("a retryable install failure is retried as a new job by the pump after the backoff; the deployment keeps its PC", async () => {
    const c = await connector(5);
    const win = await prisma.patch.create({ data: { kind: "WINDOWS", externalId: GUID, kb: "KB5000001", title: "KB5000001", severity: "CRITICAL" } });
    await deploying(c, 1, [win.id]);
    await produceConnectorDeployments();
    const [job] = await installJobs();
    await post(c, job.id, { ok: false, error: "agent offline", retryable: true });
    // backoff: no retry job yet (it would hold an install slot while waiting); the deployment keeps its PC
    expect(await installJobs()).toHaveLength(1);
    const d = await prisma.deployment.findFirstOrThrow();
    expect(d).toMatchObject({ status: "SENDING", note: expect.stringMatching(/^retry 1 scheduled after: agent offline/) });
    expect(d.nextAttemptAt.getTime()).toBeGreaterThan(Date.now());
    // due → the pump queues the retry (inside the connector's cap) for the rest of the window
    await pumpConnector(c.tenantId, c.id, new Date(d.nextAttemptAt.getTime() + 1000));
    const all = await installJobs();
    expect(all).toHaveLength(2);
    expect(all[1]).toMatchObject({ status: "QUEUED", attempts: 1, deploymentId: job.deploymentId, expiresAt: job.expiresAt });
    expect((await prisma.deployment.findFirstOrThrow()).status).toBe("SENDING");
  });

  it("Tactical natsdown: plain-words note, retried beyond MAX_JOB_ATTEMPTS while the window lasts, at most 5 min apart", async () => {
    const c = await connector(5);
    const win = await prisma.patch.create({ data: { kind: "WINDOWS", externalId: GUID, kb: "KB5000001", title: "KB5000001", severity: "CRITICAL" } });
    await deploying(c, 1, [win.id]);
    await produceConnectorDeployments();
    const natsdown = "Tactical cannot reach its NATS message bus (natsdown): the script was not sent to the PC; restart the trmm-nats container on the site: natsdown";
    let [job] = await installJobs();
    // generations 1..6 (MAX_JOB_ATTEMPTS = 5 would have failed it already)
    for (let gen = 1; gen <= 6; gen++) {
      const before = Date.now();
      await post(c, job.id, { ok: false, error: natsdown, retryable: true });
      const d = await prisma.deployment.findFirstOrThrow();
      expect(d).toMatchObject({ status: "SENDING", note: `Tactical messaging down at the site — retrying automatically (retry ${gen} scheduled)` });
      expect(d.nextAttemptAt.getTime() - before).toBeLessThanOrEqual(5 * 60_000 + 1000);
      await pumpConnector(c.tenantId, c.id, new Date(d.nextAttemptAt.getTime() + 1000));
      const all = await installJobs();
      job = all[all.length - 1];
      expect(job).toMatchObject({ status: "QUEUED", attempts: gen });
    }
  });
});

describe("routing", () => {
  it("the direct Tactical worker leaves connector-backed banks alone", async () => {
    const c = await connector(5);
    const { patch } = await sevenZip();
    await deploying(c, 1, [patch.id]);
    const tactical = { getUpdates: vi.fn(), runScript: vi.fn(), getAgent: vi.fn() } as unknown as TacticalClient;
    expect(await processQueue(tactical)).toBe(0);
    expect(tactical.runScript).not.toHaveBeenCalled();
  });
});
