/**
 * Regression tests for the deployment-pipeline review findings (C1, H1–H5, H7, M1, M3–M7, LOW, SEC #5).
 * Library calls run as a NON-owner, NON-superuser, NOBYPASSRLS role (like production's patchgate_app),
 * so every path is exercised with Row-Level Security applied; fixtures / read-backs use the superuser.
 */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { TENANT_A, asDbAttacker, configureTestEnv, resetDb } from "./helpers";
import { enrollBody, makeConnectorKey, sessionUserOf, writeRepoFile } from "./connector-helpers";

const APP_ROLE = "patchgate_app_deploy_test";
const APP_PASSWORD = "app-role-deploy-test-only-0123456789";
const repoDir = mkdtempSync(join(tmpdir(), "pg-deploy-pipe-"));
configureTestEnv({ REPO_DIR: repoDir, LOG_LEVEL: "silent" });
const adminUrl = process.env.DATABASE_URL!;
const { PrismaClient } = await import("@prisma/client");
const admin = new PrismaClient({ datasourceUrl: adminUrl });

await admin.$executeRawUnsafe(`DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${APP_ROLE}') THEN
    CREATE ROLE ${APP_ROLE} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
END
$$`);
await admin.$executeRawUnsafe(`ALTER ROLE ${APP_ROLE} PASSWORD '${APP_PASSWORD}'`);
await admin.$executeRawUnsafe(`GRANT USAGE ON SCHEMA public TO ${APP_ROLE}`);
await admin.$executeRawUnsafe(`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ${APP_ROLE}`);
await admin.$executeRawUnsafe(`GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO ${APP_ROLE}`);
await admin.$executeRawUnsafe(`GRANT patchgate_tenant TO ${APP_ROLE}`);
const appUrl = new URL(adminUrl);
appUrl.username = APP_ROLE;
appUrl.password = APP_PASSWORD;
process.env.DATABASE_URL = appUrl.toString();

const { prisma } = await import("@/lib/db");
const { withTenant } = await import("@/lib/tenancy");
const { createEnrollmentCode } = await import("@/lib/connector/admin");
const { redeemEnrollment } = await import("@/lib/connector/enroll");
const { enqueueJob, expireJobs, purgeFinishedJobs, JOB_RETENTION_MS } = await import("@/lib/connector/queue");
const { acceptResult, processJobResult, processPendingResults } = await import("@/lib/connector/results");
const { applyJobOutcome } = await import("@/lib/connector/handlers");
const { createChangeRequest, applyAction } = await import("@/lib/approvals/service");
const { startDeployment } = await import("@/lib/deploy/start");
const { produceConnectorDeployments, pumpConnector, onJobsExpired } = await import("@/lib/deploy/connector-deploy");
const { ringCounts, stopRingIfFailing } = await import("@/lib/deploy/connector-state");
const { confirmSentDeployments } = await import("@/lib/deploy/connector-confirm");
const { enforceDeployDeadlines, DEFAULT_DEPLOY_DEADLINE_DAYS } = await import("@/lib/deploy/deadline");
const { finaliseChangeRequests, runWorkerTick } = await import("@/lib/deploy/worker");
const { migrationsComplete, readiness } = await import("@/lib/health");
const { acquireLease, renewLease, releaseLease } = await import("@/lib/deploy/lease");
const { appendAudit, verifyAuditLog } = await import("@/lib/audit/service");
const { auditChainsHealthy, verifyAuditChainsIncremental } = await import("@/lib/audit/verify-incremental");

beforeEach(async () => {
  await resetDb(admin);
  await admin.$executeRawUnsafe(`DELETE FROM "ChangeRequestTarget"`);
  await admin.$executeRawUnsafe(`DELETE FROM "AuditVerifyCheckpoint"`);
});
afterAll(async () => {
  await prisma.$disconnect();
  await admin.$disconnect();
  rmSync(repoDir, { recursive: true, force: true });
});

const GUID = "55555555-5555-5555-5555-555555555555";
const INSTALL = ["DEPLOY_PACKAGE", "DEPLOY_WINDOWS", "WU_INSTALL"] as const;

async function connector(maxConcurrentInstalls: number, name = "HQ") {
  const platformAdmin = sessionUserOf(await admin.user.upsert({ where: { upn: "admin@pg" }, update: {}, create: { upn: "admin@pg", name: "A", role: "ADMIN" } }));
  const { code } = await createEnrollmentCode(platformAdmin, { tenantId: TENANT_A, name });
  const r = await redeemEnrollment(enrollBody(code, makeConnectorKey()));
  await admin.connector.update({ where: { id: r.connectorId }, data: { maxConcurrentInstalls, lastSeenAt: new Date() } });
  return { id: r.connectorId, tenantId: TENANT_A, name, maxConcurrentInstalls, bandwidthLimitMbps: null };
}
type Conn = Awaited<ReturnType<typeof connector>>;

async function sevenZip() {
  const file = writeRepoFile(repoDir, "pkgs/7zip/24.08/7z2408-x64.msi", "pretend MSI bytes for 7-Zip 24.08 (pipeline)");
  const app = await admin.app.create({ data: { wingetId: "7zip.7zip", displayName: "7-Zip", inventoryMatch: "^7-Zip", expectedPublisher: "O=Igor Pavlov", allowedDomains: [] } });
  const v = await admin.appVersion.create({
    data: {
      appId: app.id, version: "24.08", installerUrl: "https://github.com/x.msi", sha256: file.sha256, silentArgs: "", verification: "VERIFIED",
      repoPath: file.repoPath, availableAt: new Date(Date.now() - 1000), signerOrg: "Igor Pavlov",
    },
  });
  const patch = await admin.patch.create({ data: { kind: "THIRD_PARTY", externalId: "7zip.7zip@24.08", title: "7-Zip 24.08", appVersionId: v.id } });
  await admin.tenantApp.create({ data: { tenantId: TENANT_A, appId: app.id, enabledBy: "admin@pg" } });
  return { patch, file };
}

const windowsPatch = () => admin.patch.create({ data: { kind: "WINDOWS", externalId: GUID, kb: "KB5000005", title: "KB5000005", severity: "CRITICAL" } });

interface PcSpec {
  agentId?: string;
  lastWuScanAt?: Date | null;
}

/** Submitted + approved (+ started unless `start: false`) change request for PCs on connector `c` (window always open). */
async function deploying(c: Conn, pcs: number | PcSpec[], patchIds: string[], opts: { start?: boolean } = {}) {
  const specs: PcSpec[] = typeof pcs === "number" ? Array.from({ length: pcs }, () => ({})) : pcs;
  const maker = sessionUserOf(await admin.user.create({ data: { upn: `op${Math.random()}@pg`, name: "Op", role: "OPERATOR" } }));
  const checker = sessionUserOf(await admin.user.create({ data: { upn: `ap${Math.random()}@a`, name: "Ap", role: "APPROVER", tenantId: TENANT_A } }));
  const ring = await admin.ring.create({ data: { tenantId: TENANT_A, name: `R${Math.random()}`, wsusGroup: `G${Math.random()}`, order: Math.floor(Math.random() * 1e6) } });
  const window = await admin.maintenanceWindow.create({ data: { tenantId: TENANT_A, ringId: ring.id, name: "Hourly", cron: "0 * * * *", durationMin: 120, timezone: "UTC" } });
  const endpoints = [];
  for (let i = 0; i < specs.length; i++) {
    endpoints.push(
      await admin.endpoint.create({
        data: {
          tenantId: TENANT_A, tacticalAgentId: specs[i].agentId ?? `agentPIPE${String(i).padStart(4, "0")}${Math.floor(Math.random() * 1e6)}`, hostname: `PC${i}`,
          ringId: ring.id, connectorId: c.id, goarch: "amd64", lastWuScanAt: specs[i].lastWuScanAt === undefined ? new Date() : specs[i].lastWuScanAt,
        },
      }),
    );
  }
  const cr = await createChangeRequest(maker, TENANT_A, { title: "Patch Tuesday", ringId: ring.id, windowId: window.id, patchIds });
  await applyAction(maker, TENANT_A, cr.id, "submit");
  await applyAction(checker, TENANT_A, cr.id, "approve");
  if (opts.start !== false) await startDeployment(checker, TENANT_A, cr.id);
  return { crId: cr.id, ringId: ring.id, endpoints, checker };
}

async function post(c: Conn, jobId: string, result: unknown) {
  await acceptResult(c, jobId, result);
  expect(await processJobResult(c.tenantId, jobId)).toBe("applied");
}

const installJobs = (where: object = {}) => admin.connectorJob.findMany({ where: { type: { in: [...INSTALL] }, ...where }, orderBy: { createdAt: "asc" } });

async function cacheOk(c: Conn) {
  const cache = await admin.connectorJob.findFirstOrThrow({ where: { type: "CACHE_PACKAGE", status: { in: ["QUEUED", "DELIVERED"] } } });
  const pkg = (cache.payload as { package: { sha256: string; size: number; repoPath: string } }).package;
  await post(c, cache.id, { ok: true, result: { sha256: pkg.sha256, size: pkg.size, cachedPath: pkg.repoPath } });
}

/** A signed-looking job row inserted directly (state fixtures). */
async function jobRow(c: Conn, data: { type: (typeof INSTALL)[number] | "CACHE_PACKAGE" | "SCAN"; status: "SUCCEEDED" | "FAILED" | "EXPIRED" | "CANCELLED"; payload?: object; deploymentId?: string | null; completedAt?: Date; processed?: boolean; createdAt?: Date }) {
  const at = data.completedAt ?? new Date();
  return admin.connectorJob.create({
    data: {
      id: `job_${Math.random().toString(36).slice(2, 14)}${Date.now().toString(36)}`, tenantId: c.tenantId, connectorId: c.id, type: data.type, status: data.status,
      payload: data.payload ?? {}, signature: "test", expiresAt: new Date(at.getTime() + 60_000), notBefore: new Date(at.getTime() - 60_000),
      completedAt: at, processedAt: data.processed === false ? null : at, deploymentId: data.deploymentId ?? null, createdAt: data.createdAt ?? at,
      result: data.status === "SUCCEEDED" ? { ok: true, result: {} } : { ok: false, error: "x", retryable: false },
    },
  });
}

describe("C1 — Windows updates through PatchGate never hang a deployment", () => {
  it("a deployment whose WU_INSTALL already succeeded (updates now INSTALLED) moves to SENT instead of waiting for ever", async () => {
    const c = await connector(5);
    const win = await windowsPatch();
    const { endpoints } = await deploying(c, 1, [win.id]);
    const d = await admin.deployment.findFirstOrThrow();
    await admin.deployment.update({ where: { id: d.id }, data: { status: "SENDING", claimedAt: new Date() } });
    await jobRow(c, { type: "WU_INSTALL", status: "SUCCEEDED", deploymentId: d.id, payload: { agentId: endpoints[0].tacticalAgentId, updates: [], rebootPolicy: "IF_REQUIRED" } });
    // what recordInstallResult leaves behind: the update is INSTALLED, nothing NEEDED any more
    await admin.endpointPatchState.create({ data: { tenantId: TENANT_A, endpointId: endpoints[0].id, patchId: win.id, status: "INSTALLED" } });

    await pumpConnector(c.tenantId, c.id);
    expect(await admin.deployment.findUniqueOrThrow({ where: { id: d.id } })).toMatchObject({ status: "SENT" });
  });

  it("nothing needed → no Windows step (SENT); never scanned → waits (parked); undeliverable → FAILED (planning, not a ring failure)", async () => {
    const c = await connector(5);
    const win = await windowsPatch();
    await admin.winUpdate.deleteMany({ where: { id: GUID } }); // shared catalog: not emptied by resetDb
    await admin.winUpdate.create({ data: { id: GUID, revision: 1, title: "KB5000005", catalogState: "UNRESOLVABLE" } });
    const { endpoints, crId } = await deploying(c, [{}, { lastWuScanAt: null }, {}], [win.id]);
    const [upToDate, unscanned, broken] = endpoints;
    await admin.endpointPatchState.create({ data: { tenantId: TENANT_A, endpointId: upToDate.id, patchId: win.id, status: "INSTALLED" } });
    await admin.endpointPatchState.create({ data: { tenantId: TENANT_A, endpointId: broken.id, patchId: win.id, status: "NEEDED" } });

    const before = Date.now();
    await produceConnectorDeployments();
    expect(await admin.deployment.findFirstOrThrow({ where: { endpointId: upToDate.id } })).toMatchObject({ status: "SENT", note: "nothing to install on this PC" });
    const waiting = await admin.deployment.findFirstOrThrow({ where: { endpointId: unscanned.id } });
    expect(waiting).toMatchObject({ status: "QUEUED", note: expect.stringMatching(/^waiting for Windows update files: the PC has not completed a Windows Update scan/) });
    expect(waiting.nextAttemptAt.getTime()).toBeGreaterThan(before);
    expect(await admin.deployment.findFirstOrThrow({ where: { endpointId: broken.id } })).toMatchObject({ status: "FAILED", failureKind: "PLANNING", error: expect.stringMatching(/no Microsoft download/) });
    expect(await withTenant(TENANT_A, (tx) => ringCounts(tx, TENANT_A, crId))).toMatchObject({ failed: 0 });
    expect(await installJobs()).toHaveLength(0);
  });
});

describe("H1/H2 — no duplicate or orphan installs", () => {
  it("a FAILED result that is not applied yet counts as in flight: the pump does not queue the step again", async () => {
    const c = await connector(5);
    const { patch } = await sevenZip();
    await deploying(c, 1, [patch.id]);
    await produceConnectorDeployments();
    await cacheOk(c);
    const [job] = await installJobs();
    await acceptResult(c, job.id, { ok: false, error: "agent offline", retryable: true }); // stored, not applied
    await pumpConnector(c.tenantId, c.id);
    await produceConnectorDeployments();
    expect(await installJobs()).toHaveLength(1);
    expect(await processJobResult(c.tenantId, job.id)).toBe("applied");
    expect(await installJobs()).toHaveLength(1); // retry waits for its backoff (pump-queued)
  });

  it("applying the same failed result twice (crash before processedAt) schedules exactly one retry", async () => {
    const c = await connector(5);
    const job = await withTenant(TENANT_A, (tx) => enqueueJob(tx, { tenantId: TENANT_A, connectorId: c.id, type: "SCAN", payload: { agentIds: ["agentPIPE0001"] }, expiresAt: new Date(Date.now() + 6 * 3_600_000) }));
    const row = await admin.connectorJob.update({ where: { id: job.id }, data: { status: "FAILED", completedAt: new Date() } });
    const stored = { ...row, type: row.type, payload: row.payload };
    const res = { ok: false as const, error: "Tactical busy", retryable: true };
    await applyJobOutcome(stored, res, new Date());
    await applyJobOutcome(stored, res, new Date());
    const retries = await admin.connectorJob.findMany({ where: { retryOfJobId: job.id } });
    expect(retries).toHaveLength(1);
    expect(retries[0]).toMatchObject({ type: "SCAN", attempts: 1, status: "QUEUED" });
  });
});

describe("H3 — ring stop", () => {
  it("counts SENT (install reported OK) as provisional success and only INSTALL failures as failures", async () => {
    const c = await connector(5);
    const { patch } = await sevenZip();
    const { crId } = await deploying(c, 13, [patch.id]);
    const ds = await admin.deployment.findMany({ orderBy: { id: "asc" } });
    const set = (from: number, to: number, data: object) => admin.deployment.updateMany({ where: { id: { in: ds.slice(from, to).map((d) => d.id) } }, data });
    await set(0, 8, { status: "SENT", startedAt: new Date() });
    await set(8, 10, { status: "FAILED", failureKind: "INSTALL", finishedAt: new Date() });
    await set(10, 12, { status: "FAILED", failureKind: "CACHE", finishedAt: new Date() });
    // 2 of 10 install results failed (20 %) — before the fix: 2 of 2 → stopped
    expect(await withTenant(TENANT_A, (tx) => stopRingIfFailing(tx, TENANT_A, crId, new Date()))).toBe(0);
    await set(7, 8, { status: "FAILED", failureKind: "INSTALL", startedAt: null });
    expect(await withTenant(TENANT_A, (tx) => stopRingIfFailing(tx, TENANT_A, crId, new Date()))).toBe(1);
    expect(await admin.deployment.findUniqueOrThrow({ where: { id: ds[12].id } })).toMatchObject({ status: "FAILED", failureKind: "RING_STOPPED" });
  });
});

describe("H4 — one poison deployment never blocks the connector", () => {
  it("an unexpected error fails only that deployment (with a note, audited); the others get their jobs", async () => {
    const c = await connector(5);
    const { patch } = await sevenZip();
    const { endpoints } = await deploying(c, [{}, { agentId: "bad agent id!" }], [patch.id]);
    await produceConnectorDeployments();
    await cacheOk(c);
    const bad = await admin.deployment.findFirstOrThrow({ where: { endpointId: endpoints[1].id } });
    expect(bad).toMatchObject({ status: "FAILED", failureKind: "INTERNAL", error: expect.stringMatching(/^could not produce the install job/) });
    expect(await installJobs()).toEqual([expect.objectContaining({ deploymentId: (await admin.deployment.findFirstOrThrow({ where: { endpointId: endpoints[0].id } })).id })]);
    expect(await admin.auditEvent.count({ where: { tenantId: TENANT_A, action: "deployment.failed", entityId: bad.id } })).toBe(1);
    expect(await verifyAuditLog(TENANT_A)).toMatchObject({ valid: true });
  });
});

describe("H5 / M1 — outcome unknown and window expiry", () => {
  beforeEach(() => admin.tenant.update({ where: { id: TENANT_A }, data: { windowsUpdateSource: "WSUS" } }));

  it("outcomeUnknown: never failed or retried; SENT with the expected GUIDs for inventory confirmation; not a ring failure", async () => {
    const c = await connector(5);
    const win = await windowsPatch();
    const { crId } = await deploying(c, 1, [win.id]);
    await produceConnectorDeployments();
    const [job] = await installJobs();
    await post(c, job.id, { ok: false, error: "connection lost while the installer ran", retryable: true, outcomeUnknown: true });
    expect(await admin.deployment.findFirstOrThrow()).toMatchObject({ status: "SENT", targetGuids: [GUID], note: expect.stringMatching(/^outcome unknown/) });
    expect(await installJobs()).toHaveLength(1);
    expect(await admin.connectorJob.count({ where: { type: "RESET_APPROVALS" } })).toBe(0);
    expect(await admin.auditEvent.count({ where: { action: "deployment.outcome_unknown", tenantId: TENANT_A } })).toBe(1);
    expect(await withTenant(TENANT_A, (tx) => ringCounts(tx, TENANT_A, crId))).toMatchObject({ failed: 0 });
  });

  it("a delivered job that expires keeps its expected GUIDs (no false SUCCEEDED); a late failure still fails it", async () => {
    const c = await connector(5);
    const win = await windowsPatch();
    const { endpoints } = await deploying(c, 1, [win.id]);
    await produceConnectorDeployments();
    const [job] = await installJobs();
    await admin.connectorJob.update({ where: { id: job.id }, data: { status: "DELIVERED", deliveredAt: new Date() } });
    await onJobsExpired(await expireJobs(new Date(job.expiresAt.getTime() + 1000)));
    expect(await admin.deployment.findFirstOrThrow()).toMatchObject({ status: "SENT", targetGuids: [GUID] });

    // fresh inventory that does NOT show the update → not confirmed
    await admin.endpoint.update({ where: { id: endpoints[0].id }, data: { lastScanAt: new Date(Date.now() + 1000) } });
    await confirmSentDeployments(TENANT_A);
    expect((await admin.deployment.findFirstOrThrow()).status).toBe("SENT");

    await post(c, job.id, { ok: false, error: "install failed (late)", retryable: false });
    expect(await admin.deployment.findFirstOrThrow()).toMatchObject({ status: "FAILED", failureKind: "INSTALL" });
  });
});

describe("M3 — deployment deadline", () => {
  it("times out what has not started, audits it, and the change request finalises", async () => {
    const c = await connector(5);
    const { patch } = await sevenZip();
    const { crId } = await deploying(c, 2, [patch.id]);
    const cr = await admin.changeRequest.findUniqueOrThrow({ where: { id: crId } });
    expect(cr.deployDeadlineAt!.getTime()).toBeGreaterThan(Date.now() + (DEFAULT_DEPLOY_DEADLINE_DAYS - 1) * 86_400_000);
    const [a] = await admin.deployment.findMany({ orderBy: { id: "asc" } });
    await admin.deployment.update({ where: { id: a.id }, data: { status: "SENT", startedAt: new Date() } });
    await admin.changeRequest.update({ where: { id: crId }, data: { deployDeadlineAt: new Date(Date.now() - 1000) } });

    expect(await enforceDeployDeadlines()).toMatchObject({ changeRequests: 1, timedOut: 1 });
    expect(await admin.deployment.findFirstOrThrow({ where: { id: { not: a.id } } })).toMatchObject({ status: "TIMED_OUT", failureKind: "DEADLINE", note: expect.stringMatching(/deadline/) });
    expect(await admin.auditEvent.count({ where: { action: "change_request.deadline_reached", entityId: crId, tenantId: TENANT_A } })).toBe(1);
    await admin.deployment.update({ where: { id: a.id }, data: { status: "SUCCEEDED", finishedAt: new Date() } });
    await finaliseChangeRequests();
    expect((await admin.changeRequest.findUniqueOrThrow({ where: { id: crId } })).status).toBe("PARTIAL");
  });
});

describe("M4 — site cache failures are retried before deployments fail", () => {
  it("defers after a failed download, retries up to the cap, then fails the waiting deployments (kind CACHE)", async () => {
    const c = await connector(5);
    const { patch } = await sevenZip();
    await deploying(c, 2, [patch.id]);
    const t0 = Date.now();
    const at = async (offsetMin: number) => {
      const now = new Date(t0 + offsetMin * 60_000);
      await admin.connector.update({ where: { id: c.id }, data: { lastSeenAt: now } });
      await pumpConnector(c.tenantId, c.id, now);
    };
    const failNewestCache = async () => {
      const job = await admin.connectorJob.findFirstOrThrow({ where: { type: "CACHE_PACKAGE", status: "QUEUED" }, orderBy: { createdAt: "desc" } });
      await post(c, job.id, { ok: false, error: "proxy refused the download", retryable: false });
    };
    await at(0);
    for (let attempt = 1; attempt <= 2; attempt++) {
      await failNewestCache();
      expect(await admin.deployment.count({ where: { status: "QUEUED" } })).toBe(2); // deferred, still waiting
      await at(attempt * 31); // retry due → a new download attempt
    }
    await failNewestCache(); // third failure in a row: the cap
    await at(3 * 31);
    expect(await admin.connectorJob.count({ where: { type: "CACHE_PACKAGE" } })).toBe(3);
    expect(await admin.deployment.findMany({ select: { status: true, failureKind: true } })).toEqual([
      { status: "FAILED", failureKind: "CACHE" },
      { status: "FAILED", failureKind: "CACHE" },
    ]);
  });
});

describe("M5 — pump scale + retention", () => {
  it("QUEUED deployments follow their PC to another connector; started ones stay", async () => {
    const c1 = await connector(5, "HQ");
    const c2 = await connector(5, "Branch");
    const { patch } = await sevenZip();
    const { endpoints } = await deploying(c1, 2, [patch.id]);
    const [moving, running] = await admin.deployment.findMany({ orderBy: { endpointId: "asc" } });
    expect(moving.connectorId).toBe(c1.id);
    await admin.deployment.update({ where: { id: running.id }, data: { status: "SENDING" } });
    await withTenant(TENANT_A, (tx) => tx.endpoint.updateMany({ where: { id: { in: endpoints.map((e) => e.id) } }, data: { connectorId: c2.id } }));
    expect((await admin.deployment.findUniqueOrThrow({ where: { id: moving.id } })).connectorId).toBe(c2.id);
    expect((await admin.deployment.findUniqueOrThrow({ where: { id: running.id } })).connectorId).toBe(c1.id);
  });

  it("purges old finished jobs but keeps unfinished deployments' jobs and the newest cache job per package", async () => {
    const c = await connector(5);
    const { patch } = await sevenZip();
    await deploying(c, 1, [patch.id]);
    const d = await admin.deployment.findFirstOrThrow();
    await admin.deployment.update({ where: { id: d.id }, data: { status: "SENT", startedAt: new Date() } });
    const old = new Date(Date.now() - JOB_RETENTION_MS - 86_400_000);
    const older = new Date(old.getTime() - 3_600_000);
    const pkg = { package: { sha256: "a".repeat(64) } };
    const scan = await jobRow(c, { type: "SCAN", status: "SUCCEEDED", completedAt: old });
    const install = await jobRow(c, { type: "DEPLOY_PACKAGE", status: "SUCCEEDED", completedAt: old, deploymentId: d.id });
    const cacheOld = await jobRow(c, { type: "CACHE_PACKAGE", status: "FAILED", completedAt: older, payload: pkg });
    const cacheNew = await jobRow(c, { type: "CACHE_PACKAGE", status: "SUCCEEDED", completedAt: old, payload: pkg });
    const recent = await jobRow(c, { type: "SCAN", status: "SUCCEEDED" });

    expect(await purgeFinishedJobs()).toBe(2);
    const left = new Set((await admin.connectorJob.findMany({ select: { id: true } })).map((j) => j.id));
    expect(left.has(scan.id)).toBe(false);
    expect(left.has(cacheOld.id)).toBe(false);
    expect([install.id, cacheNew.id, recent.id].every((id) => left.has(id))).toBe(true);
  });
});

describe("M7 — result processing", () => {
  it("applies install / cache results before older inventory pages", async () => {
    const c = await connector(5);
    const collect = await jobRow(c, { type: "SCAN", status: "SUCCEEDED", processed: false, completedAt: new Date(Date.now() - 60_000) });
    const install = await jobRow(c, { type: "DEPLOY_PACKAGE", status: "SUCCEEDED", processed: false });
    await admin.connectorJob.update({ where: { id: collect.id }, data: { result: { ok: true, result: { requested: [], failed: [] } } } });
    await admin.connectorJob.update({ where: { id: install.id }, data: { result: { ok: true, result: { outcome: "INSTALLED" } } } });
    expect(await processPendingResults(1)).toMatchObject({ applied: 1 });
    expect((await admin.connectorJob.findUniqueOrThrow({ where: { id: install.id } })).processedAt).not.toBeNull();
    expect((await admin.connectorJob.findUniqueOrThrow({ where: { id: collect.id } })).processedAt).toBeNull();
  });

  it("a held lease can be renewed (long ticks keep their lease)", async () => {
    const holder = await acquireLease("test-renew", 2_000);
    expect(holder).not.toBeNull();
    const before = (await admin.workerLease.findUniqueOrThrow({ where: { name: "test-renew" } })).expiresAt;
    expect(await renewLease("test-renew", holder!, 60_000)).toBe(true);
    expect((await admin.workerLease.findUniqueOrThrow({ where: { name: "test-renew" } })).expiresAt.getTime()).toBeGreaterThan(before.getTime());
    expect(await renewLease("test-renew", "someone-else", 60_000)).toBe(false);
    await releaseLease("test-renew", holder!);
  });
});

describe("LOW — retries respect the install cap", () => {
  it("a due retry waits while the connector's install slots are taken", async () => {
    const c = await connector(1);
    const { patch } = await sevenZip();
    await deploying(c, 2, [patch.id]);
    await produceConnectorDeployments();
    await cacheOk(c);
    const [first] = await installJobs();
    await post(c, first.id, { ok: false, error: "agent offline", retryable: true });
    // the freed slot went to the other PC; the retry (when due) must not exceed the cap of 1
    const d = await admin.deployment.findUniqueOrThrow({ where: { id: first.deploymentId! } });
    await pumpConnector(c.tenantId, c.id, new Date(d.nextAttemptAt.getTime() + 1000));
    expect(await admin.connectorJob.count({ where: { type: { in: [...INSTALL] }, status: { in: ["QUEUED", "DELIVERED"] } } })).toBe(1);
    expect(await installJobs()).toHaveLength(2);
  });
});

describe("SEC #5 — targets are fixed at submission", () => {
  it("PCs added to the ring after approval are not deployed to; the approval records the target count", async () => {
    const c = await connector(5);
    const { patch } = await sevenZip();
    const { crId, ringId, checker } = await deploying(c, 2, [patch.id], { start: false });
    await admin.endpoint.create({ data: { tenantId: TENANT_A, tacticalAgentId: "agentLATE00001", hostname: "LATE", ringId, connectorId: c.id } });
    await startDeployment(checker, TENANT_A, crId);
    expect(await admin.deployment.count({ where: { changeRequestId: crId } })).toBe(2);
    expect(await admin.deployment.count({ where: { endpoint: { tacticalAgentId: "agentLATE00001" } } })).toBe(0);
    expect((await admin.changeRequest.findUniqueOrThrow({ where: { id: crId } })).targetCount).toBe(2);
    const approve = await admin.auditEvent.findFirstOrThrow({ where: { action: "change_request.approve", entityId: crId } });
    expect(approve.payload).toMatchObject({ targetEndpoints: 2 });
    expect((await admin.deployment.findFirstOrThrow({ where: { changeRequestId: crId } })).connectorId).toBe(c.id);
  });
});

describe("H7 — incremental audit verification", () => {
  it("verifies only new events, detects a truncated tail, and readiness reads the stored verdict", async () => {
    for (let i = 0; i < 3; i++) await appendAudit({ tenantId: TENANT_A, actor: "t", action: "test.event", entity: "T", entityId: String(i) });
    expect(await verifyAuditChainsIncremental()).toMatchObject({ valid: true, verified: 3 });
    expect(await auditChainsHealthy()).toBe(true);
    for (let i = 3; i < 5; i++) await appendAudit({ tenantId: TENANT_A, actor: "t", action: "test.event", entity: "T", entityId: String(i) });
    expect(await verifyAuditChainsIncremental()).toMatchObject({ valid: true, verified: 2 });
    expect(await verifyAuditChainsIncremental()).toMatchObject({ valid: true, verified: 0 }); // nothing new: no scan

    const last = await admin.auditEvent.findFirstOrThrow({ where: { tenantId: TENANT_A }, orderBy: { seq: "desc" } });
    await asDbAttacker(admin, `DELETE FROM "AuditEvent" WHERE "seq" = ${last.seq}`);
    expect(await verifyAuditChainsIncremental()).toMatchObject({ valid: false, brokenChains: 1 });
    expect(await auditChainsHealthy()).toBe(false);
    expect(await admin.auditVerifyCheckpoint.findUniqueOrThrow({ where: { chain: TENANT_A } })).toMatchObject({ valid: false, problem: expect.stringMatching(/missing/) });
  });
});

describe("readiness + hosted mode", () => {
  /** Run `fn` against fake _prisma_migrations rows inside a transaction that is always rolled back. */
  async function withFakeMigrations(rows: string, fn: (tx: Parameters<typeof migrationsComplete>[0]) => Promise<boolean>): Promise<boolean> {
    let result = false;
    await admin
      .$transaction(async (tx) => {
        await tx.$executeRawUnsafe(`INSERT INTO "_prisma_migrations" ("id", "checksum", "migration_name", "started_at", "finished_at", "rolled_back_at", "applied_steps_count") VALUES ${rows}`);
        result = await fn(tx);
        throw new Error("rollback");
      })
      .catch((e: unknown) => {
        if (!(e instanceof Error) || e.message !== "rollback") throw e;
      });
    return result;
  }

  it("migrations: a rolled-back attempt that was re-applied is fine; an unfinished or only-rolled-back one is not", async () => {
    expect(await migrationsComplete(admin)).toBe(true);
    const ok = `('t1', 'x', 'zz_test_m', now(), NULL, now(), 0), ('t2', 'x', 'zz_test_m', now(), now(), NULL, 1)`;
    expect(await withFakeMigrations(ok, (tx) => migrationsComplete(tx))).toBe(true);
    expect(await withFakeMigrations(`('t3', 'x', 'zz_test_m', now(), NULL, now(), 0)`, (tx) => migrationsComplete(tx))).toBe(false);
    expect(await withFakeMigrations(`('t4', 'x', 'zz_test_m', now(), NULL, NULL, 0)`, (tx) => migrationsComplete(tx))).toBe(false);
  });

  it("readiness reports the repository quota (report-only) and only booleans", async () => {
    const r = await readiness();
    expect(r.ready).toBe(true);
    expect(Object.values(r.checks).every((v) => v === null || typeof v === "boolean")).toBe(true);
    expect(r.checks).toHaveProperty("repoQuota");
  });

  it("without a direct Tactical link (hosted mode) the legacy steps are skipped, the tick stays ok", async () => {
    const r = await runWorkerTick({ tactical: null, siem: null });
    expect(r.ok).toBe(true);
    expect(r.steps.deployQueue).toMatch(/^skipped: direct Tactical link not configured/);
    expect(r.steps.reconcile).toMatch(/^skipped/);
  });
});
