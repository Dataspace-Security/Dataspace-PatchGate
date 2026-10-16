/**
 * Compliance reports on a seeded dataset, running as a NON-owner, NOBYPASSRLS role (like production):
 * exact figures (compliance, gap ages, rings, top missing, apps, change requests, connector uptime, audit
 * evidence), bank isolation, the streamed CSV and the audited printable export.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { TENANT_A, TENANT_B, configureTestEnv, resetDb } from "./helpers";

const APP_ROLE = "patchgate_app_reports_test";
const APP_PASSWORD = "reports-role-test-only-0123456789";

configureTestEnv();
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
const { buildBankReport, buildPlatformSummary } = await import("@/lib/reports/build");
const { parsePeriod } = await import("@/lib/reports/period");
const { exportCsv, generatePrintable } = await import("@/lib/reports/service");
const { appendAudit } = await import("@/lib/audit/service");
const { verifyChainIncremental } = await import("@/lib/audit/verify-incremental");

const NOW = new Date("2026-10-16T12:00:00Z");
const DAY = 86_400_000;
const daysAgo = (d: number) => new Date(NOW.getTime() - d * DAY);
// 1 – 10 October 2026 (to inclusive) = 240 h
const PERIOD = parsePeriod({ period: "custom", from: "2026-10-01", to: "2026-10-10" });
const user = { id: "u-report", upn: "auditor@a.example", name: "Auditor", role: "VIEWER" as const, tenantId: TENANT_A };

const MY_TABLES = ["Notification", "NotificationSetting", "NotificationOptOut", "NotificationAlert", "ConnectorOutage"];
const ids: Record<string, string> = {};

async function seed(): Promise<void> {
  await resetDb(admin);
  for (const t of MY_TABLES) await admin.$executeRawUnsafe(`DELETE FROM "${t}"`);
  await admin.$executeRawUnsafe(`DELETE FROM "ChangeRequestApproval"`).catch(() => undefined);

  const maker = await admin.user.create({ data: { upn: "maker@a.example", name: "Maker", role: "OPERATOR", tenantId: TENANT_A } });
  const checker = await admin.user.create({ data: { upn: "checker@a.example", name: "Checker", role: "APPROVER", tenantId: TENANT_A } });
  const r0 = await admin.ring.create({ data: { tenantId: TENANT_A, name: "Ring0-Test", wsusGroup: "R0", order: 0 } });
  const r1 = await admin.ring.create({ data: { tenantId: TENANT_A, name: "Ring1-Prod", wsusGroup: "R1", order: 1 } });
  const rb = await admin.ring.create({ data: { tenantId: TENANT_B, name: "B-Ring", wsusGroup: "RB", order: 0 } });

  const ep = async (tenantId: string, host: string, ringId: string, scanned = true) =>
    (await admin.endpoint.create({ data: { tenantId, tacticalAgentId: `agent-${host}`, hostname: host, ringId, lastScanAt: scanned ? daysAgo(1) : null } })).id;
  const e1 = await ep(TENANT_A, "A-PC1", r0.id);
  const e2 = await ep(TENANT_A, "=A-PC2", r0.id); // formula-like hostname: CSV must neutralise it
  const e3 = await ep(TENANT_A, "A-PC3", r0.id);
  const e4 = await ep(TENANT_A, "A-PC4", r1.id);
  await ep(TENANT_A, "A-PC5", r1.id, false); // never scanned: not counted as compliant
  const b1 = await ep(TENANT_B, "B-PC1", rb.id);

  const patch = async (key: string, severity: "CRITICAL" | "IMPORTANT" | "MODERATE", releasedDaysAgo: number | null, supersededById?: string) =>
    (await admin.patch.create({ data: { kind: "WINDOWS", externalId: `guid-${key}`, kb: `KB${key}`, title: `Update ${key}`, severity, releasedAt: releasedDaysAgo === null ? null : daysAgo(releasedDaysAgo), supersededById } })).id;
  const p1 = await patch("1", "CRITICAL", 3);
  const p2 = await patch("2", "IMPORTANT", 40);
  const p3 = await patch("3", "CRITICAL", 100);
  const p4 = await patch("4", "MODERATE", 10);
  const p5 = await patch("5", "CRITICAL", 200, p1); // superseded by p1: ignored
  const p6 = await patch("6", "CRITICAL", null);

  const st = (tenantId: string, endpointId: string, patchId: string, status: "NEEDED" | "FAILED" | "INSTALLED") => ({ tenantId, endpointId, patchId, status });
  await admin.endpointPatchState.createMany({
    data: [
      st(TENANT_A, e1, p1, "NEEDED"),
      st(TENANT_A, e2, p2, "FAILED"),
      st(TENANT_A, e2, p3, "NEEDED"),
      st(TENANT_A, e3, p1, "INSTALLED"),
      st(TENANT_A, e3, p5, "NEEDED"),
      st(TENANT_A, e4, p4, "NEEDED"),
      st(TENANT_B, b1, p1, "NEEDED"),
      st(TENANT_B, b1, p6, "NEEDED"),
    ],
  });

  // Third-party app enabled for bank A: latest verified 2.0 (1.0 older); one endpoint still needs 2.0.
  const app = await admin.app.create({ data: { wingetId: "Vendor.Tool", displayName: "Vendor Tool", inventoryMatch: "Vendor Tool" } });
  await admin.appVersion.create({ data: { appId: app.id, version: "1.0", installerUrl: "-", sha256: "1".repeat(64), silentArgs: "", verification: "VERIFIED" } });
  const v2 = await admin.appVersion.create({ data: { appId: app.id, version: "2.0", installerUrl: "-", sha256: "2".repeat(64), silentArgs: "", verification: "VERIFIED" } });
  await admin.appVersion.create({ data: { appId: app.id, version: "3.0", installerUrl: "-", sha256: "3".repeat(64), silentArgs: "", verification: "HELD", holdReason: "SIGNER_CHANGED" } });
  const tp = await admin.patch.create({ data: { kind: "THIRD_PARTY", externalId: `${app.id}@2.0`, title: "Vendor Tool 2.0", appVersionId: v2.id } });
  await admin.endpointPatchState.create({ data: st(TENANT_A, e4, tp.id, "NEEDED") });
  await admin.tenantApp.create({ data: { tenantId: TENANT_A, appId: app.id, enabledBy: "x" } });
  await admin.discoveredApp.create({ data: { tenantId: TENANT_A, key: "vendor tool|vendor", displayName: "Vendor Tool", appId: app.id, endpointCount: 3, versions: ["1.0", "2.0"] } });
  await admin.discoveredApp.create({ data: { tenantId: TENANT_A, key: "game|x", displayName: "Some Game", ignored: true, endpointCount: 2, versions: ["5"] } });
  await admin.discoveredApp.create({ data: { tenantId: TENANT_B, key: "bgame|x", displayName: "B Ignored", ignored: true, endpointCount: 9, versions: [] } });

  // Change requests: one in the period (2 ok, 1 failed), one emergency in the period, one before it, one of bank B.
  const cr = (tenantId: string, ringId: string, createdById: string, title: string, createdAt: Date, extra: Record<string, unknown> = {}) =>
    admin.changeRequest.create({ data: { tenantId, ringId, createdById, title, createdAt, ...extra } });
  const inP = await cr(TENANT_A, r0.id, maker.id, "October patches", new Date("2026-10-02T09:00:00Z"), {
    status: "PARTIAL", approvedById: checker.id, submittedAt: new Date("2026-10-02T10:00:00Z"), decidedAt: new Date("2026-10-02T11:00:00Z"), completedAt: new Date("2026-10-03T11:00:00Z"), targetCount: 3, ticketRef: "CHG-1",
  });
  ids.inPeriod = inP.id;
  for (const [endpointId, status] of [[e1, "SUCCEEDED"], [e2, "SUCCEEDED"], [e3, "FAILED"]] as const) {
    await admin.deployment.create({ data: { tenantId: TENANT_A, changeRequestId: inP.id, endpointId, status } });
  }
  const emg = await cr(TENANT_A, r1.id, maker.id, "Zero-day fix", new Date("2026-10-05T09:00:00Z"), { status: "APPROVED", emergency: true, emergencyReason: "CVE exploited", requiredApprovals: 2, submittedAt: new Date("2026-10-05T09:10:00Z") });
  ids.emergency = emg.id;
  await cr(TENANT_A, r0.id, maker.id, "September patches", new Date("2026-09-10T09:00:00Z"), { status: "COMPLETED", completedAt: new Date("2026-09-12T09:00:00Z") });
  const bMaker = await admin.user.create({ data: { upn: "maker@b.example", name: "B", role: "OPERATOR", tenantId: TENANT_B } });
  await cr(TENANT_B, rb.id, bMaker.id, "Bank B change", new Date("2026-10-03T09:00:00Z"));

  // Connector with one 3-hour outage inside the period; bank B connector offline (must not leak).
  const c = await admin.connector.create({ data: { tenantId: TENANT_A, name: "Head office", publicKey: "k", enrolledAt: new Date("2026-09-01T00:00:00Z"), lastSeenAt: NOW } });
  await admin.connectorOutage.create({ data: { tenantId: TENANT_A, connectorId: c.id, startedAt: new Date("2026-10-04T00:00:00Z"), endedAt: new Date("2026-10-04T03:00:00Z") } });
  const cb = await admin.connector.create({ data: { tenantId: TENANT_B, name: "B site", publicKey: "k", enrolledAt: new Date("2026-09-01T00:00:00Z") } });
  await admin.connectorOutage.create({ data: { tenantId: TENANT_B, connectorId: cb.id, startedAt: new Date("2026-10-02T00:00:00Z") } });

  // Audit chain of bank A: 2 events, verified.
  await appendAudit({ tenantId: TENANT_A, actor: "x", action: "test.a1", entity: "T", entityId: "1" });
  await appendAudit({ tenantId: TENANT_A, actor: "x", action: "test.a2", entity: "T", entityId: "2" });
  await verifyChainIncremental(TENANT_A);
}

beforeAll(seed, 120_000);
afterAll(async () => {
  await prisma.$disconnect();
  await admin.$disconnect();
});

describe("bank compliance report", () => {
  it("computes fleet, compliance, rings, gap ages and top missing patches exactly", async () => {
    const r = await buildBankReport(TENANT_A, PERIOD, user.upn, NOW);
    expect(r.meta).toMatchObject({ bankId: TENANT_A, bankName: "Default bank", periodLabel: "2026-10-01 – 2026-10-10", generatedBy: user.upn });
    // e1 (critical gap), e2 (important + critical) non-compliant; e3 (superseded only) + e4 (moderate + 3rd-party) compliant; e5 never scanned.
    expect(r.fleet).toEqual({ endpoints: 5, scanned: 4, compliant: 2, compliancePct: 50, criticalMissing: 2, importantMissing: 1 });
    expect(r.rings.map((x) => [x.ring, x.endpoints, x.scanned, x.compliant, x.compliancePct])).toEqual([
      ["Ring0-Test", 3, 3, 1, 33.3],
      ["Ring1-Prod", 2, 1, 1, 100],
    ]);
    const gaps = r.gaps.map((g) => `${g.severity}:${g.bucket}:${g.missing}:${g.endpoints}`).sort();
    expect(gaps).toEqual(["CRITICAL:0-7:1:1", "CRITICAL:>90:1:1", "IMPORTANT:31-90:1:1"]);
    expect(r.topMissing).toHaveLength(5); // KB1, KB2, KB3, KB4 and the third-party patch — never the superseded KB5
    expect(r.topMissing.map((p) => p.kb)).not.toContain("KB5");
    expect(r.topMissing[0]).toMatchObject({ severity: "CRITICAL", endpoints: 1 });
  });

  it("reports app currency, change requests (maker / approver / results), emergencies and exceptions of the period", async () => {
    const r = await buildBankReport(TENANT_A, PERIOD, user.upn, NOW);
    expect(r.apps).toEqual([{ app: "Vendor Tool", wingetId: "Vendor.Tool", latestVerified: "2.0", installedVersions: ["2.0", "1.0"], endpointsWithApp: 3, endpointsMissingLatest: 1 }]);
    expect(r.changes.map((c) => c.title)).toEqual(["October patches", "Zero-day fix"]);
    expect(r.changes[0]).toMatchObject({ maker: "maker@a.example", approvers: ["checker@a.example"], status: "PARTIAL", targets: 3, succeeded: 2, failed: 1, ticketRef: "CHG-1", emergency: false });
    expect(r.changes[1]).toMatchObject({ emergency: true, emergencyReason: "CVE exploited" });
    expect(r.exceptions.map((e) => [e.kind, e.name])).toEqual([
      ["ignored-app", "Some Game"],
      ["held-package", "Vendor Tool 3.0"],
    ]);
    expect(r.exceptions[1].detail).toContain("enabled for this bank");
  });

  it("computes connector uptime from outages and carries the audit-chain evidence", async () => {
    const r = await buildBankReport(TENANT_A, PERIOD, user.upn, NOW);
    expect(r.connectors).toEqual([{ connector: "Head office", status: "ACTIVE", lastSeenAt: NOW, outages: 1, downtimeMinutes: 180, uptimePct: 98.8, offlineNow: false }]);
    expect(r.evidence).toMatchObject({ chain: TENANT_A, verified: true, coversPeriod: true, problem: null });
    const head = await admin.auditEvent.findFirstOrThrow({ where: { tenantId: TENANT_A }, orderBy: { seq: "desc" } });
    // Events were appended "now" (after the period) → the period head is the last event before 11 Oct: none.
    expect(r.evidence.headSeq).toBeNull();
    const all = await buildBankReport(TENANT_A, parsePeriod({ period: "custom", from: "2026-10-01", to: new Date().toISOString().slice(0, 10) }), user.upn, NOW);
    expect(all.evidence).toMatchObject({ headSeq: head.seq.toString(), headHash: head.hash, verified: true, coversPeriod: true });
    expect(all.evidence.eventsInPeriod).toBeGreaterThanOrEqual(2);
  });

  it("bank B's report never contains bank A's data (and the reverse)", async () => {
    const b = await buildBankReport(TENANT_B, PERIOD, "x@b.example", NOW);
    expect(b.fleet).toMatchObject({ endpoints: 1, scanned: 1, compliant: 0, criticalMissing: 2 });
    expect(b.gaps.map((g) => g.bucket).sort()).toEqual(["0-7", "unknown"]);
    expect(b.changes.map((c) => c.title)).toEqual(["Bank B change"]);
    expect(b.apps).toEqual([]);
    expect(b.exceptions.filter((e) => e.kind === "ignored-app").map((e) => e.name)).toEqual(["B Ignored"]);
    expect(b.connectors).toMatchObject([{ connector: "B site", offlineNow: true }]);
    const a = await buildBankReport(TENANT_A, PERIOD, user.upn, NOW);
    expect(JSON.stringify(a)).not.toMatch(/B-PC1|Bank B change|B site|B Ignored/);
    // RLS: bank B's scope sees none of bank A's outages even without a tenant filter.
    expect(await withTenant(TENANT_B, (tx) => tx.connectorOutage.count())).toBe(1);
  });

  it("all-banks summary has one row per bank", async () => {
    const s = await buildPlatformSummary(PERIOD, "padmin@pg.example", NOW);
    const byBank = Object.fromEntries(s.banks.map((b) => [b.bankId, b]));
    expect(byBank[TENANT_A]).toMatchObject({ endpoints: 5, compliancePct: 50, criticalMissing: 2, changes: 2, failedChanges: 1, emergencyChanges: 1, connectorsOfflineNow: 0, auditChainValid: true });
    expect(byBank[TENANT_B]).toMatchObject({ endpoints: 1, compliancePct: 0, changes: 1, connectorsOfflineNow: 1 });
  });
});

describe("exports", () => {
  it("printable HTML carries bank, period, generator and SHA-256, and generating it is audited on the bank chain", async () => {
    const before = await admin.auditEvent.count({ where: { tenantId: TENANT_A, action: "report.generate" } });
    const { html, sha256 } = await generatePrintable(user, { kind: "bank", tenantId: TENANT_A, bankName: "Default bank" }, PERIOD);
    expect(sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(html).toContain("Patch compliance report — Default bank");
    expect(html).toContain(sha256);
    expect(html).toContain("auditor@a.example");
    expect(html).toContain("2026-10-01 – 2026-10-10");
    expect(html).not.toContain("<script");
    const ev = await admin.auditEvent.findFirstOrThrow({ where: { tenantId: TENANT_A, action: "report.generate" }, orderBy: { seq: "desc" } });
    expect(await admin.auditEvent.count({ where: { tenantId: TENANT_A, action: "report.generate" } })).toBe(before + 1);
    expect(ev.payload).toMatchObject({ format: "html", sha256, period: PERIOD.label });
  });

  it("streams the non-compliant endpoint CSV (formula-safe) and exports sections; each export is audited", async () => {
    const scope = { kind: "bank" as const, tenantId: TENANT_A, bankName: "Default bank" };
    const nc = await exportCsv(user, scope, PERIOD, "noncompliant");
    expect(typeof nc.body).not.toBe("string");
    const text = await new Response(nc.body as ReadableStream<Uint8Array>).text();
    const lines = text.trim().split("\r\n");
    expect(lines[0]).toBe("endpoint_id,hostname,site,ring,last_scan_at,missing_critical_important,missing_critical,oldest_missing_released_at");
    expect(lines).toHaveLength(3);
    expect(text).toContain("A-PC1");
    expect(text).toContain(",'=A-PC2,");
    expect(text).not.toContain("B-PC1");
    expect(nc.filename).toBe("patchgate-default-bank-noncompliant-2026-10-01.csv");

    const changes = await exportCsv(user, scope, PERIOD, "changes");
    expect(String(changes.body).split("\r\n")[0]).toContain("maker,approvers");
    expect(String(changes.body)).toContain("CHG-1");
    const emergency = await exportCsv(user, scope, PERIOD, "emergency");
    expect(String(emergency.body).trim().split("\r\n")).toHaveLength(2);
    const audits = await admin.auditEvent.findMany({ where: { tenantId: TENANT_A, action: "report.generate", payload: { path: ["format"], equals: "csv" } } });
    expect(audits.length).toBeGreaterThanOrEqual(3);

    const all = await exportCsv({ ...user, tenantId: null, upn: "padmin@pg.example" }, { kind: "all" }, PERIOD, "summary");
    expect(String(all.body)).toContain("Demo Bank B");
    expect(await admin.auditEvent.count({ where: { tenantId: null, action: "report.generate" } })).toBe(1);
  });
});
