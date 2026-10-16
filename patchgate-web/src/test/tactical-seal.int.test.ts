/**
 * Tactical seal (RUNBOOK "Tactical is sealed"): TACTICAL_AUDIT_SYNC results → TacticalActivity (once per
 * Tactical entry, RLS), bank-chain audit, critical notification, cursor + follow-up page; approval drift on
 * COLLECT → alert + RESET_APPROVALS; schedules; "Sync agents now" / "Request scan of all PCs" for connector banks.
 */
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { TENANT_A, TENANT_B, configureTestEnv, resetDb } from "./helpers";
import { enrollBody, makeConnectorKey, sessionUserOf } from "./connector-helpers";

configureTestEnv({ LOG_LEVEL: "error", AGENT_SYNC_MINUTES: "15" });
const { prisma } = await import("@/lib/db");
const { withTenant } = await import("@/lib/tenancy");
const { createEnrollmentCode } = await import("@/lib/connector/admin");
const { redeemEnrollment } = await import("@/lib/connector/enroll");
const { enqueueJob, claimJobs } = await import("@/lib/connector/queue");
const { acceptResult, processJobResult } = await import("@/lib/connector/results");
const { scheduleConnectorInventory } = await import("@/lib/scan/connector-schedule");
const { requestConnectorAgentSync, requestConnectorScan } = await import("@/lib/scan/scan-request");
const { acknowledgeTacticalActivity, listTacticalActivity } = await import("@/lib/connector/tactical-activity");

beforeEach(() => resetDb(prisma));
afterAll(async () => prisma.$disconnect());

async function mkUser(upn: string, role: "ADMIN" | "AUDITOR", tenantId: string | null) {
  return sessionUserOf(await prisma.user.create({ data: { upn, name: upn, role, tenantId } }));
}

async function connector(tenantId = TENANT_A, name = "HQ") {
  const admin = sessionUserOf(await prisma.user.upsert({ where: { upn: "enrol@pg.example" }, update: {}, create: { upn: "enrol@pg.example", name: "E", role: "ADMIN" } }));
  const { code } = await createEnrollmentCode(admin, { tenantId, name });
  const r = await redeemEnrollment(enrollBody(code, makeConnectorKey()));
  await prisma.connector.update({ where: { id: r.connectorId }, data: { lastSeenAt: new Date() } });
  return { id: r.connectorId, tenantId, name, maxConcurrentInstalls: 50, bandwidthLimitMbps: null };
}
type Conn = Awaited<ReturnType<typeof connector>>;

async function roundTrip(c: Conn, type: "TACTICAL_AUDIT_SYNC" | "COLLECT", payload: unknown, result: unknown) {
  const job = await withTenant(c.tenantId, (tx) =>
    enqueueJob(tx, { tenantId: c.tenantId, connectorId: c.id, type, payload: payload as never, expiresAt: new Date(Date.now() + 3_600_000) }),
  );
  await claimJobs(c.tenantId, c.id);
  await acceptResult(c, job.id, { ok: true, result });
  expect(await processJobResult(c.tenantId, job.id)).toBe("applied");
  return job.id;
}

/** Shaped like the connector's mapping of Tactical 1.5.2 AuditLog rows. */
const ev = (id: number, over: Record<string, unknown> = {}) => ({
  id,
  ts: `2026-10-16T10:${String(id).padStart(2, "0")}:00+00:00`,
  actor: "tacticaladmin",
  action: "login",
  objectType: "user",
  agentHostname: null,
  agentId: null,
  message: "tacticaladmin logged in successfully",
  ip: "10.0.0.5",
  ...over,
});

const AGENT = "agentAAAA1111";
const G = (n: number) => `${String(n).padStart(8, "0")}-0000-4000-8000-000000000000`;
const upd = (id: number, guid: string, action: string, installed = false) => ({ id, guid, kb: `KB${5000000 + id}`, title: `Update ${id}`, installed, action, severity: "Important" });

describe("TACTICAL_AUDIT_SYNC results", () => {
  it("stores each out-of-band entry once, audits it on the bank chain, notifies admins and advances the cursor", async () => {
    await mkUser("admin@pg.example", "ADMIN", null);
    await mkUser("admin@a.example", "ADMIN", TENANT_A);
    await mkUser("auditor@a.example", "AUDITOR", TENANT_A);
    await mkUser("admin@b.example", "ADMIN", TENANT_B);
    const c = await connector();
    const result = {
      events: [
        ev(3),
        ev(4, { action: "execute_script", objectType: "agent", agentHostname: "DESKTOP-Q6U5I2R", agentId: AGENT, message: 'tacticaladmin ran script: "x" on DESKTOP-Q6U5I2R' }),
        ev(5, { actor: "patchgate-svc", action: "execute_script", objectType: "agent" }), // PatchGate's own: dropped server-side too
      ],
      cursor: 9,
      more: false,
    };
    await roundTrip(c, "TACTICAL_AUDIT_SYNC", { afterId: 0, limit: 500 }, result);

    const rows = await prisma.tacticalActivity.findMany({ orderBy: { tacticalId: "asc" } });
    expect(rows.map((r) => [r.tenantId, r.source, r.tacticalId, r.action])).toEqual([
      [TENANT_A, "AUDIT_LOG", 3, "login"],
      [TENANT_A, "AUDIT_LOG", 4, "execute_script"],
    ]);
    expect(await prisma.connector.findUniqueOrThrow({ where: { id: c.id } })).toMatchObject({ tacticalAuditCursor: 9, tacticalHumanSeenAt: expect.any(Date) });
    const audits = await prisma.auditEvent.findMany({ where: { action: "tactical.out_of_band_action" } });
    expect(audits).toHaveLength(2);
    expect(audits.every((a) => a.tenantId === TENANT_A && a.entityId === c.id)).toBe(true);
    expect(audits.map((a) => a.actor).sort()).toEqual(["tactical:tacticaladmin", "tactical:tacticaladmin"]);

    const mails = await prisma.notification.findMany({ where: { event: "TACTICAL_OUT_OF_BAND", channel: "EMAIL" } });
    expect(mails.map((m) => m.target).sort()).toEqual(["admin@a.example", "admin@pg.example", "enrol@pg.example"]); // platform + bank A admins; not the auditor, not bank B
    expect(mails[0]!.severity).toBe("critical");
    expect(mails[0]!.subject).toContain("2 action(s) in Tactical outside PatchGate");

    // the same entries again (overlapping page / re-delivery): nothing new, no second alert
    await roundTrip(c, "TACTICAL_AUDIT_SYNC", { afterId: 0, limit: 500 }, result);
    expect(await prisma.tacticalActivity.count()).toBe(2);
    expect(await prisma.auditEvent.count({ where: { action: "tactical.out_of_band_action" } })).toBe(2);
    expect(await prisma.notification.count({ where: { event: "TACTICAL_OUT_OF_BAND", channel: "EMAIL" } })).toBe(3);
    expect((await prisma.connector.findUniqueOrThrow({ where: { id: c.id } })).tacticalAuditCursor).toBe(9); // never moves back
  });

  it("more → the next page is queued at once from the new cursor; reset → an audit-log gap activity", async () => {
    const c = await connector();
    await roundTrip(c, "TACTICAL_AUDIT_SYNC", { afterId: 0, limit: 500 }, { events: [ev(1)], cursor: 1, more: true });
    const next = await prisma.connectorJob.findMany({ where: { type: "TACTICAL_AUDIT_SYNC", status: "QUEUED" } });
    expect(next.map((j) => j.payload)).toEqual([{ afterId: 1, limit: 500 }]);

    await roundTrip(c, "TACTICAL_AUDIT_SYNC", { afterId: 1, limit: 500 }, { events: [ev(1, { ts: "2026-10-17T08:00:00+00:00" })], cursor: 1, more: false, reset: true });
    const gap = await prisma.tacticalActivity.findMany({ where: { source: "AUDIT_RESET" } });
    expect(gap).toHaveLength(1);
    // id 1 of the new (reset) log is a different entry than the old id 1: stored as well
    expect(await prisma.tacticalActivity.count({ where: { source: "AUDIT_LOG", tacticalId: 1 } })).toBe(2);
  });

  it("is row-level isolated per bank; ADMIN acknowledges (audited), another bank cannot", async () => {
    const c = await connector();
    await roundTrip(c, "TACTICAL_AUDIT_SYNC", { afterId: 0, limit: 500 }, { events: [ev(1), ev(2)], cursor: 2, more: false });
    expect(await withTenant(TENANT_B, (tx) => tx.tacticalActivity.count())).toBe(0);
    expect(await withTenant(TENANT_A, (tx) => tx.tacticalActivity.count())).toBe(2);
    expect((await listTacticalActivity({ kind: "tenant", tenantId: TENANT_B })).rows).toHaveLength(0);
    expect(await listTacticalActivity({ kind: "tenant", tenantId: TENANT_A })).toMatchObject({ unacknowledged: 2 });
    expect((await listTacticalActivity({ kind: "platform" })).rows[0]).toMatchObject({ tenantName: "Default bank", connectorName: "HQ" });

    const bankB = await mkUser("admin@b.example", "ADMIN", TENANT_B);
    await expect(acknowledgeTacticalActivity(bankB, TENANT_A, null, null)).rejects.toThrow(/not found/);
    const bankA = await mkUser("admin@a.example", "ADMIN", TENANT_A);
    expect(await acknowledgeTacticalActivity(bankA, TENANT_A, null, "planned break-glass, ticket CHG-1")).toBe(2);
    expect(await acknowledgeTacticalActivity(bankA, TENANT_A, null, null)).toBe(0);
    expect(await listTacticalActivity({ kind: "tenant", tenantId: TENANT_A })).toMatchObject({ unacknowledged: 0 });
    const ack = await prisma.auditEvent.findFirstOrThrow({ where: { action: "tactical.activity_acknowledged" } });
    expect(ack).toMatchObject({ tenantId: TENANT_A, actor: "admin@a.example", payload: expect.objectContaining({ count: 2, note: "planned break-glass, ticket CHG-1" }) });
  });
});

describe("approval drift (Tactical does not audit approvals)", () => {
  it("alerts an approval PatchGate did not set and resets the PC's approvals; PatchGate's own approvals are fine", async () => {
    const c = await connector();
    await prisma.endpoint.create({ data: { tenantId: TENANT_A, tacticalAgentId: AGENT, hostname: "DESKTOP-Q6U5I2R", connectorId: c.id } });
    // PatchGate approved G(1) earlier (job finished and expired)
    const own = await withTenant(TENANT_A, (tx) =>
      enqueueJob(tx, { tenantId: TENANT_A, connectorId: c.id, type: "DEPLOY_WINDOWS", payload: { agentId: AGENT, guids: [G(1)], rebootPolicy: "NEVER" }, expiresAt: new Date(Date.now() + 3_600_000) }),
    );
    await prisma.connectorJob.update({ where: { id: own.id }, data: { status: "SUCCEEDED", processedAt: new Date(), expiresAt: new Date(Date.now() - 86_400_000) } });

    const page = { agents: [{ agentId: AGENT, updates: [upd(1, G(1), "approve"), upd(2, G(2), "approve"), upd(3, G(3), "approve", true), upd(4, G(4), "nothing")] }] };
    await roundTrip(c, "COLLECT", { agentIds: [AGENT], updates: true, software: false, agent: false }, page);
    const drift = await prisma.tacticalActivity.findMany({ where: { source: "APPROVAL_DRIFT" } });
    expect(drift).toHaveLength(1);
    expect(drift[0]).toMatchObject({ agentId: AGENT, agentHostname: "DESKTOP-Q6U5I2R", action: "winupdate_approve" });
    expect(drift[0]!.message).toContain("KB5000002");
    expect(drift[0]!.message).not.toContain("KB5000001");
    expect(drift[0]!.message).toContain("approvals reset by PatchGate");
    const resets = await prisma.connectorJob.findMany({ where: { type: "RESET_APPROVALS" } });
    expect(resets.map((r) => r.payload)).toEqual([{ agentId: AGENT }]);
    expect(await prisma.auditEvent.count({ where: { action: "tactical.out_of_band_action", tenantId: TENANT_A } })).toBe(1);

    // same drift seen again the same day: no second alert, no second reset while one is outstanding
    await roundTrip(c, "COLLECT", { agentIds: [AGENT], updates: true, software: false, agent: false }, page);
    expect(await prisma.tacticalActivity.count({ where: { source: "APPROVAL_DRIFT" } })).toBe(1);
    expect(await prisma.connectorJob.count({ where: { type: "RESET_APPROVALS" } })).toBe(1);
  });

  it("does not reset while a PatchGate deployment is in flight on that PC (alert only)", async () => {
    const c = await connector();
    await prisma.endpoint.create({ data: { tenantId: TENANT_A, tacticalAgentId: AGENT, hostname: "PC1", connectorId: c.id } });
    await withTenant(TENANT_A, (tx) =>
      enqueueJob(tx, { tenantId: TENANT_A, connectorId: c.id, type: "DEPLOY_WINDOWS", payload: { agentId: AGENT, guids: [G(1)], rebootPolicy: "NEVER" }, expiresAt: new Date(Date.now() + 3_600_000) }),
    );
    await roundTrip(c, "COLLECT", { agentIds: [AGENT], updates: true, software: false, agent: false }, { agents: [{ agentId: AGENT, updates: [upd(1, G(1), "approve"), upd(9, G(9), "approve")] }] });
    const drift = await prisma.tacticalActivity.findFirstOrThrow({ where: { source: "APPROVAL_DRIFT" } });
    expect(drift.message).toContain("not reset");
    expect(await prisma.connectorJob.count({ where: { type: "RESET_APPROVALS" } })).toBe(0);
  });
});

describe("schedules", () => {
  it("audit read every 10 min from the stored cursor, never twice while outstanding; approval re-check after human activity", async () => {
    const c = await connector();
    await prisma.connector.update({ where: { id: c.id }, data: { tacticalAuditCursor: 42 } });
    await prisma.endpoint.create({ data: { tenantId: TENANT_A, tacticalAgentId: AGENT, hostname: "PC1", connectorId: c.id } });
    const first = await scheduleConnectorInventory();
    expect(first).toMatchObject({ tacticalAudit: 1, approvalCheck: 0 });
    expect((await prisma.connectorJob.findFirstOrThrow({ where: { type: "TACTICAL_AUDIT_SYNC" } })).payload).toEqual({ afterId: 42, limit: 500 });
    expect(await scheduleConnectorInventory()).toMatchObject({ tacticalAudit: 0 });

    await prisma.connector.update({ where: { id: c.id }, data: { tacticalHumanSeenAt: new Date() } });
    expect(await scheduleConnectorInventory()).toMatchObject({ approvalCheck: 1 });
    const check = await prisma.connectorJob.findFirstOrThrow({ where: { type: "COLLECT", payload: { path: ["software"], equals: false } } });
    expect(check.payload).toEqual({ agentIds: [AGENT], updates: true, software: false, agent: false });
    expect(await scheduleConnectorInventory()).toMatchObject({ approvalCheck: 0 });
  });

  it("SYNC_AGENTS every AGENT_SYNC_MINUTES (15)", async () => {
    const c = await connector();
    expect(await scheduleConnectorInventory()).toMatchObject({ sync: 1 });
    const job = await prisma.connectorJob.findFirstOrThrow({ where: { type: "SYNC_AGENTS" } });
    await prisma.connectorJob.update({ where: { id: job.id }, data: { status: "SUCCEEDED", completedAt: new Date(), processedAt: new Date(), createdAt: new Date(Date.now() - 10 * 60_000) } });
    expect(await scheduleConnectorInventory()).toMatchObject({ sync: 0 });
    await prisma.connectorJob.update({ where: { id: job.id }, data: { createdAt: new Date(Date.now() - 16 * 60_000) } });
    expect(await scheduleConnectorInventory()).toMatchObject({ sync: 1 });
    expect(await prisma.connectorJob.count({ where: { connectorId: c.id, type: "SYNC_AGENTS" } })).toBe(2);
  });
});

describe("Endpoints page actions for connector banks", () => {
  it("Sync agents now: one SYNC_AGENTS per connector, de-duplicated, audited", async () => {
    const c = await connector();
    expect(await requestConnectorAgentSync(TENANT_A, "admin@a.example")).toMatchObject({ connectors: 1, syncQueued: 1 });
    expect(await requestConnectorAgentSync(TENANT_A, "admin@a.example")).toMatchObject({ syncQueued: 0, message: expect.stringContaining("already in progress") });
    expect(await prisma.connectorJob.count({ where: { connectorId: c.id, type: "SYNC_AGENTS" } })).toBe(1);
    expect(await prisma.auditEvent.count({ where: { tenantId: TENANT_A, action: "endpoints.sync_requested" } })).toBe(2);
  });

  it("Request scan: sync first, every PC due, WU_SCAN requested after the sync (waits for the catalog)", async () => {
    const c = await connector();
    await prisma.endpoint.create({ data: { tenantId: TENANT_A, tacticalAgentId: AGENT, hostname: "PC1", connectorId: c.id, lastScanAt: new Date(), lastScanRequestedAt: new Date() } });
    const r = await requestConnectorScan(TENANT_A, "admin@a.example");
    expect(r).toMatchObject({ queued: 1, connectors: 1, syncQueued: 1, wuScan: "catalog_missing" });
    expect(r.message).toContain("Syncing PCs from Tactical, then scanning");
    expect(r.message).toContain("Windows scan starts automatically");
    expect(await prisma.endpoint.findFirstOrThrow({ where: { tacticalAgentId: AGENT } })).toMatchObject({ lastScanAt: null, lastScanRequestedAt: null });
    expect((await prisma.connector.findUniqueOrThrow({ where: { id: c.id } })).wuScanRequestedAt).toBeInstanceOf(Date);
    // repeated clicks do not stack sync jobs
    expect(await requestConnectorScan(TENANT_A, "admin@a.example")).toMatchObject({ syncQueued: 0 });
    expect(await prisma.connectorJob.count({ where: { type: "SYNC_AGENTS" } })).toBe(1);
    const audit = await prisma.auditEvent.findFirstOrThrow({ where: { tenantId: TENANT_A, action: "endpoints.scan_requested" } });
    expect(audit.payload).toMatchObject({ count: 1, syncQueued: 1, wuScan: "catalog_missing" });

    // WSUS banks: no WU_SCAN request
    await prisma.tenant.update({ where: { id: TENANT_A }, data: { windowsUpdateSource: "WSUS" } });
    await prisma.connector.update({ where: { id: c.id }, data: { wuScanRequestedAt: null } });
    expect(await requestConnectorScan(TENANT_A, "admin@a.example")).toMatchObject({ wuScan: "not_used" });
    expect((await prisma.connector.findUniqueOrThrow({ where: { id: c.id } })).wuScanRequestedAt).toBeNull();
  });

  it("WU_SCAN runs right after the requested sync once the verified catalog is cached (SYNC_AGENTS → SCAN → WU_SCAN)", async () => {
    const c = await connector();
    await prisma.endpoint.create({ data: { tenantId: TENANT_A, tacticalAgentId: AGENT, hostname: "PC1", connectorId: c.id } });
    await prisma.wsusScanCab.create({ data: { sha256: "a".repeat(64), sizeBytes: 1000, sourceUrl: "https://example.invalid/wsusscn2.cab", verification: "VERIFIED", repoPath: "winupdate/wsusscn2-test.cab" } });
    // the daily WU_SCAN already ran an hour ago: without a request nothing would be due today
    const daily = await withTenant(TENANT_A, async (tx) => {
      const cab = (await import("@/lib/winupdate/hooks")).wuScanCab;
      const pkg = (await cab(tx))!;
      return enqueueJob(tx, { tenantId: TENANT_A, connectorId: c.id, type: "WU_SCAN", payload: { agentIds: [AGENT], scanCab: pkg }, expiresAt: new Date(Date.now() + 3_600_000) });
    });
    await prisma.connectorJob.update({ where: { id: daily.id }, data: { status: "SUCCEEDED", completedAt: new Date(), processedAt: new Date(), createdAt: new Date(Date.now() - 3_600_000) } });

    expect(await requestConnectorScan(TENANT_A, "admin@a.example")).toMatchObject({ wuScan: "catalog_pending" });
    // site download of the catalog finishes; the sync is still outstanding → no WU_SCAN yet
    await prisma.connectorJob.updateMany({ where: { type: "CACHE_PACKAGE" }, data: { status: "SUCCEEDED", completedAt: new Date(), processedAt: new Date() } });
    expect(await scheduleConnectorInventory()).toMatchObject({ wuScan: 0, scan: 1 });
    // the sync result was applied → the requested WU_SCAN is queued once, and the request is cleared
    await prisma.connectorJob.updateMany({ where: { type: "SYNC_AGENTS" }, data: { status: "SUCCEEDED", completedAt: new Date(), processedAt: new Date() } });
    expect(await scheduleConnectorInventory()).toMatchObject({ wuScan: 1 });
    expect((await prisma.connector.findUniqueOrThrow({ where: { id: c.id } })).wuScanRequestedAt).toBeNull();
    expect(await scheduleConnectorInventory()).toMatchObject({ wuScan: 0 });
    expect(await prisma.connectorJob.count({ where: { type: "WU_SCAN", status: "QUEUED" } })).toBe(1);
    // a click while the catalog is cached reports "requested"
    expect(await requestConnectorScan(TENANT_A, "admin@a.example")).toMatchObject({ wuScan: "requested" });
  });
});
