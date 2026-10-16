/**
 * /api/metrics on seeded data, as the production-like NON-owner, NOBYPASSRLS runtime role (like
 * app-role.int.test.ts): cross-bank aggregates go through withPlatform(), so Row-Level Security applies.
 * Also covers the tick → WorkerStepRun timing path.
 */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { TENANT_A, TENANT_B, configureTestEnv, resetDb } from "./helpers";

const APP_ROLE = "patchgate_app_test";
const APP_PASSWORD = "app-role-test-only-0123456789";
const METRICS_TOKEN = "metrics-test-token-".padEnd(48, "x");
const repoDir = mkdtempSync(join(tmpdir(), "pg-metrics-"));

configureTestEnv({ REPO_DIR: repoDir, METRICS_TOKEN });
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
const { GET } = await import("@/app/api/metrics/route");
const { resetOpsSnapshotCache, opsSnapshot } = await import("@/lib/metrics/collect");
const { stepTimer } = await import("@/lib/metrics/worker-steps");
const { runWorkerTick } = await import("@/lib/deploy/worker");
const { appendAudit } = await import("@/lib/audit/service");
const { verifyAuditChainsIncremental } = await import("@/lib/audit/verify-incremental");

const HOUR = 3_600_000;
const ago = (ms: number) => new Date(Date.now() - ms);
const HB_OK = { version: "1.4.0", cache: { files: 3, bytes: 100, freeBytes: 5_000_000_000 }, tactical: { reachable: true, agents: 3 }, siem: { configured: true } };

async function seed(): Promise<void> {
  await resetDb(admin);
  await admin.$executeRawUnsafe(`DELETE FROM "WorkerStepRun"`);
  const maker = await admin.user.create({ data: { upn: "maker@bank-a.test", name: "Maker", role: "ADMIN", tenantId: TENANT_A } });
  const ringA = await admin.ring.create({ data: { tenantId: TENANT_A, name: "Ring0", wsusGroup: "R0", order: 0 } });

  const a1 = await admin.connector.create({ data: { tenantId: TENANT_A, name: "HQ", publicKey: "k1", version: "1.4.0", lastSeenAt: ago(60_000), heartbeat: HB_OK } });
  await admin.connector.create({ data: { tenantId: TENANT_A, name: "DR", publicKey: "k2", version: "1.3.0", lastSeenAt: ago(2 * HOUR) } });
  await admin.connector.create({ data: { tenantId: TENANT_A, name: "Old", publicKey: "k3", status: "REVOKED" } });
  const b1 = await admin.connector.create({ data: { tenantId: TENANT_B, name: "B-HQ", publicKey: "k4", version: "1.4.0", lastSeenAt: ago(30_000), heartbeat: HB_OK } });

  const crit = await admin.patch.create({ data: { kind: "WINDOWS", externalId: "11111111-0000-0000-0000-000000000001", title: "Critical fix", severity: "CRITICAL" } });
  const imp = await admin.patch.create({ data: { kind: "WINDOWS", externalId: "11111111-0000-0000-0000-000000000002", title: "Important fix", severity: "IMPORTANT" } });
  const ep = (tenantId: string, id: string, scanned: boolean, connectorId: string) =>
    admin.endpoint.create({ data: { tenantId, tacticalAgentId: `agent-${id}`, hostname: id, connectorId, ringId: tenantId === TENANT_A ? ringA.id : null, lastScanAt: scanned ? ago(HOUR) : null } });
  const e1 = await ep(TENANT_A, "a1", true, a1.id); // critical + important missing
  await ep(TENANT_A, "a2", true, a1.id); // up to date
  await ep(TENANT_A, "a3", false, a1.id); // never scanned
  const e4 = await ep(TENANT_B, "b1", true, b1.id); // important missing
  await admin.endpointPatchState.createMany({
    data: [
      { tenantId: TENANT_A, endpointId: e1.id, patchId: crit.id, status: "NEEDED" },
      { tenantId: TENANT_A, endpointId: e1.id, patchId: imp.id, status: "FAILED" },
      { tenantId: TENANT_B, endpointId: e4.id, patchId: imp.id, status: "NEEDED" },
    ],
  });

  const cr = await admin.changeRequest.create({ data: { tenantId: TENANT_A, title: "Oct", ringId: ringA.id, status: "PENDING_APPROVAL", createdById: maker.id, submittedAt: ago(30 * HOUR) } });
  await admin.deployment.create({ data: { tenantId: TENANT_A, changeRequestId: cr.id, endpointId: e1.id, status: "QUEUED" } });

  const job = (tenantId: string, connectorId: string, status: "QUEUED" | "DELIVERED" | "FAILED" | "SUCCEEDED", extra: Record<string, unknown> = {}) =>
    admin.connectorJob.create({ data: { tenantId, connectorId, type: "COLLECT", payload: {}, signature: "sig", status, expiresAt: new Date(Date.now() + 24 * HOUR), ...extra } });
  await job(TENANT_A, a1.id, "QUEUED", { createdAt: ago(2 * HOUR), notBefore: ago(2 * HOUR) });
  await job(TENANT_A, a1.id, "QUEUED", { notBefore: new Date(Date.now() + 5 * HOUR) }); // scheduled for a later window: not late
  await job(TENANT_A, a1.id, "FAILED", { completedAt: ago(HOUR), processedAt: ago(HOUR), type: "DEPLOY_WINDOWS" });
  await job(TENANT_A, a1.id, "SUCCEEDED", { completedAt: ago(HOUR), processedAt: ago(HOUR) });
  await job(TENANT_B, b1.id, "SUCCEEDED", { completedAt: ago(HOUR), processedAt: ago(HOUR) });

  await admin.fetchRun.create({ data: { source: "winget:Vendor.App", startedAt: ago(HOUR), finishedAt: ago(HOUR), ok: false, message: "FAILED: x" } });
  await admin.fetchRun.create({ data: { source: "winget:Vendor.Other", startedAt: ago(2 * HOUR), finishedAt: ago(2 * HOUR), ok: true } });
  await admin.fetchRun.create({ data: { source: "repo-quota", startedAt: ago(60_000), finishedAt: ago(60_000), ok: true, message: "1.00 of 500.00 GB used" } });

  // Audit chains (written + verified by the runtime role, like the worker does).
  await appendAudit({ tenantId: TENANT_A, actor: "test", action: "test.event", entity: "Test", entityId: "1" });
  await appendAudit({ actor: "test", action: "test.platform", entity: "Test", entityId: "2" });
  await verifyAuditChainsIncremental();
}

function scrape(token: string | null = METRICS_TOKEN): Promise<Response> {
  return GET(new Request("http://localhost/api/metrics", { headers: token ? { authorization: `Bearer ${token}` } : {} }));
}

function sample(text: string, series: string): number | undefined {
  const line = text.split("\n").find((l) => l.startsWith(`${series} `));
  return line === undefined ? undefined : Number(line.slice(series.length + 1).replace("+Inf", "Infinity"));
}

describe("/api/metrics (runtime role, RLS applied)", () => {
  let text = "";

  beforeAll(async () => {
    await seed();
    // The tick records step timings; hosted mode (no direct Tactical) keeps it offline.
    const timer = stepTimer();
    const r = await runWorkerTick({ tactical: null, siem: null, onStep: timer.onStep });
    await timer.finish(true, r.ok);
    resetOpsSnapshotCache();
    const res = await scrape();
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toMatch(/^text\/plain; version=0\.0\.4/);
    text = await res.text();
  }, 300_000); // a full tick is ~40 interactive transactions on the slow dev Postgres

  afterAll(async () => {
    await admin.$disconnect();
    await prisma.$disconnect();
    rmSync(repoDir, { recursive: true, force: true });
  });

  it("really runs as a non-owner role without BYPASSRLS", async () => {
    const [me] = await prisma.$queryRaw<{ super: boolean; bypass: boolean; owner: string }[]>`
      SELECT r.rolsuper AS super, r.rolbypassrls AS bypass, pg_get_userbyid(c.relowner) AS owner
        FROM pg_roles r, pg_class c WHERE r.rolname = current_user AND c.relname = 'Endpoint'`;
    expect(me).toEqual({ super: false, bypass: false, owner: expect.not.stringMatching(APP_ROLE) });
  });

  it("refuses a missing or wrong bearer token", async () => {
    expect((await scrape(null)).status).toBe(401);
    const wrong = await scrape("y".repeat(48));
    expect(wrong.status).toBe(401);
    expect(await wrong.text()).not.toContain("patchgate_");
  });

  it("counts endpoints and compliance per bank (no cross-bank bleed)", () => {
    expect(sample(text, 'patchgate_endpoints{bank="default"}')).toBe(3);
    expect(sample(text, 'patchgate_endpoints{bank="bank-b"}')).toBe(1);
    expect(sample(text, 'patchgate_compliance_ratio{bank="default"}')).toBeCloseTo(1 / 3, 6);
    expect(sample(text, 'patchgate_compliance_ratio{bank="bank-b"}')).toBe(0);
    expect(sample(text, 'patchgate_compliance_endpoints{bank="default",state="not_scanned"}')).toBe(1);
    expect(sample(text, 'patchgate_endpoints_missing_severity{bank="default",severity="critical"}')).toBe(1);
    expect(sample(text, 'patchgate_endpoints_missing_severity{bank="default",severity="important"}')).toBe(1);
    expect(sample(text, 'patchgate_endpoints_missing_severity{bank="bank-b",severity="critical"}')).toBe(0);
    expect(sample(text, 'patchgate_endpoints_missing_severity{bank="bank-b",severity="important"}')).toBe(1);
  });

  it("reports connectors online/offline and last-seen age", () => {
    expect(sample(text, 'patchgate_connectors{bank="default",state="online"}')).toBe(1);
    expect(sample(text, 'patchgate_connectors{bank="default",state="offline"}')).toBe(1);
    expect(sample(text, 'patchgate_connectors{bank="default",state="revoked"}')).toBe(1);
    expect(sample(text, 'patchgate_connectors{bank="bank-b",state="offline"}')).toBe(0);
    expect(sample(text, 'patchgate_connector_up{bank="default",connector="DR"}')).toBe(0);
    expect(sample(text, 'patchgate_connector_last_seen_age_seconds{bank="default",connector="DR"}')).toBeGreaterThan(7000);
    expect(sample(text, 'patchgate_connector_cache_free_bytes{bank="default",connector="HQ"}')).toBe(5_000_000_000);
    expect(sample(text, 'patchgate_connector_siem_relay_ok{bank="default",connector="HQ"}')).toBe(1);
  });

  it("reports the job backlog (due jobs only for the age), failures and approvals", () => {
    // 2 seeded + whatever the tick's scheduler enqueued
    expect(sample(text, 'patchgate_jobs_open{bank="default",status="QUEUED",type="COLLECT"}')).toBeGreaterThanOrEqual(2);
    const age = sample(text, 'patchgate_jobs_oldest_queued_age_seconds{bank="default"}')!;
    expect(age).toBeGreaterThan(7000);
    expect(age).toBeLessThan(7400);
    // bank B only has jobs the tick just enqueued
    expect(sample(text, 'patchgate_jobs_oldest_queued_age_seconds{bank="bank-b"}')).toBeLessThan(600);
    expect(sample(text, 'patchgate_jobs_failed_24h{bank="default",status="FAILED",type="DEPLOY_WINDOWS"}')).toBe(1);
    expect(sample(text, 'patchgate_jobs_succeeded_24h{bank="default"}')).toBe(1);
    expect(sample(text, 'patchgate_jobs_succeeded_24h{bank="bank-b"}')).toBe(1);
    expect(sample(text, 'patchgate_deployments_active{bank="default",status="QUEUED"}')).toBe(1);
    expect(sample(text, 'patchgate_change_requests_pending_approval{bank="default"}')).toBe(1);
    expect(sample(text, 'patchgate_change_requests_pending_approval_oldest_age_seconds{bank="default"}')).toBeGreaterThan(29 * 3600);
    expect(sample(text, 'patchgate_change_requests_pending_approval{bank="bank-b"}')).toBe(0);
  });

  it("reports platform signals: audit chains, fetch runs, quota, worker steps", () => {
    expect(sample(text, 'patchgate_audit_chain_valid{chain="default"}')).toBe(1);
    expect(sample(text, 'patchgate_audit_chain_valid{chain="platform"}')).toBe(1);
    expect(sample(text, "patchgate_siem_configured")).toBe(0);
    expect(sample(text, 'patchgate_fetch_runs_failed_24h{source="winget"}')).toBe(1);
    expect(sample(text, 'patchgate_fetch_runs_24h{source="winget"}')).toBe(2);
    expect(text).not.toContain('source="repo-quota"');
    expect(sample(text, "patchgate_repo_used_bytes")).toBe(1024 ** 3);
    expect(sample(text, "patchgate_repo_quota_ok")).toBe(1);
    expect(sample(text, 'patchgate_worker_step_runs_total{step="tick"}')).toBe(1);
    expect(sample(text, 'patchgate_worker_step_last_ok{step="finalise"}')).toBe(1);
    expect(sample(text, 'patchgate_worker_step_last_duration_seconds{step="auditVerify"}')).toBeGreaterThanOrEqual(0);
    expect(sample(text, "patchgate_ready")).toBe(1);
    expect(text).not.toContain("patchgate_metrics_collect_errors{");
  });

  it("accumulates step counters across ticks and keeps the last success", async () => {
    const timer = stepTimer();
    timer.onStep("finalise", "FAILED: boom", 12);
    await timer.finish(true, false);
    const rows = await prisma.workerStepRun.findMany({ where: { step: { in: ["finalise", "tick"] } }, orderBy: { step: "asc" } });
    const fin = rows.find((r) => r.step === "finalise")!;
    expect(Number(fin.runs)).toBe(2);
    expect(Number(fin.failures)).toBe(1);
    expect(fin.lastOk).toBe(false);
    expect(fin.lastSuccessAt).not.toBeNull();
    expect(fin.lastStatus).toBe("FAILED: boom");
    expect(Number(rows.find((r) => r.step === "tick")!.runs)).toBe(2);
    // a skipped tick (lease held elsewhere) records nothing
    await stepTimer().finish(false, false);
    expect(Number((await prisma.workerStepRun.findUnique({ where: { step: "tick" } }))!.runs)).toBe(2);
  });

  it("serves concurrent scrapes from one cached snapshot", async () => {
    resetOpsSnapshotCache();
    const [a, b] = await Promise.all([opsSnapshot(), opsSnapshot()]);
    expect(a.collect.fastAt).toBe(b.collect.fastAt);
    expect(a.banks.map((x) => x.slug).sort()).toEqual(["bank-b", "default"]);
  });
});
