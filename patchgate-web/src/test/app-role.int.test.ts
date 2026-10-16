/**
 * Runs the app as a NON-owner, NON-superuser, NOBYPASSRLS database role — like production's
 * `patchgate_app` (deploy/postgres/initdb/10-patchgate-roles.sh). The dev/test login is a superuser
 * (which bypasses RLS and hides missing scopes), so this file is the one that proves every path
 * works with Row-Level Security actually applied to the runtime role:
 *  - unscoped queries see nothing; withTenant/withPlatform see exactly their scope;
 *  - audit appends from unscoped transactions (fetcher / auth / admin code) still land in the right chain;
 *  - a full worker tick (deploy queue, reconcile, finalise, SIEM export) and a fetcher trust decision.
 */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { TacticalClient } from "@/lib/tactical/client";
import type { SyslogSender } from "@/lib/siem/syslog";
import { TENANT_A, TENANT_B, asSessionUser, configureTestEnv, resetDb } from "./helpers";

const APP_ROLE = "patchgate_app_test";
const APP_PASSWORD = "app-role-test-only-0123456789";
const repoDir = mkdtempSync(join(tmpdir(), "pg-approle-"));

configureTestEnv({ REPO_DIR: repoDir, NOTIFY_WEBHOOK_ALLOWED_HOSTS: "hooks.approle.example" });
const adminUrl = process.env.DATABASE_URL!;
const { PrismaClient } = await import("@prisma/client");
// Superuser connection: fixtures + role setup only (it bypasses RLS).
const admin = new PrismaClient({ datasourceUrl: adminUrl });

// Production-like runtime role: DML on every table, member of the RLS role, nothing else.
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

// Everything below talks to the DB as the runtime role.
const { prisma } = await import("@/lib/db");
const { withTenant, withPlatform } = await import("@/lib/tenancy");
const { appendAudit, verifyAuditLog } = await import("@/lib/audit/service");
const { auditExportStatus } = await import("@/lib/audit/export");
const { createChangeRequest, applyAction } = await import("@/lib/approvals/service");
const { startDeployment } = await import("@/lib/deploy/start");
const { runWorkerTick } = await import("@/lib/deploy/worker");
const { decideMirror } = await import("@/lib/fetch/tactical");
const { ingestDueEndpoints } = await import("@/lib/scan/ingest");
const { createEnrollmentCode } = await import("@/lib/connector/admin");
const { redeemEnrollment } = await import("@/lib/connector/enroll");
const { authorizeBundleAccess, auditBundleDownload } = await import("@/lib/connector/bundle-access");
const { updateNotificationSettings, getNotificationSettings } = await import("@/lib/notify/settings");
const { drainLegacyWebhooks } = await import("@/lib/notify/webhook-rotation");
const { authKeyring } = await import("@/lib/auth/enc-keys");
const { enrollBody, makeConnectorKey } = await import("./connector-helpers");

const GUID = "33333333-3333-3333-3333-333333333333";

function fakeTactical(installed: () => boolean): TacticalClient {
  return {
    listAgents: vi.fn(async () => []),
    getAgent: vi.fn(async () => ({ version: "2.11.0", goarch: "amd64" })),
    scanUpdates: vi.fn(async () => {}),
    getUpdates: vi.fn(async () => [{ id: 1, guid: GUID, kb: "KB3", title: "t", installed: installed(), action: "approve" as const, severity: "Critical" }]),
    setUpdateAction: vi.fn(async () => {}),
    installApproved: vi.fn(async () => {}),
    getSoftware: vi.fn(async () => [{ name: "7-Zip", version: "24.0" }]),
    refreshSoftware: vi.fn(async () => {}),
    runScript: vi.fn(async () => "PATCHGATE_RESULT=OK"),
  };
}

function memorySiem(fail = false): SyslogSender & { lines: string[] } {
  const lines: string[] = [];
  return {
    target: "memory://siem",
    lines,
    send: async (l) => {
      if (fail) throw new Error("SIEM unreachable (test)");
      lines.push(...l);
    },
  };
}

beforeEach(() => resetDb(admin));
afterAll(async () => {
  await prisma.$disconnect();
  await admin.$disconnect();
  rmSync(repoDir, { recursive: true, force: true });
});

describe("runtime role is subject to Row-Level Security", () => {
  it("is not the owner/superuser; unscoped reads see nothing, scoped ones see exactly their bank", async () => {
    await admin.ring.create({ data: { tenantId: TENANT_A, name: "R", wsusGroup: "R", order: 0 } });
    await admin.ring.create({ data: { tenantId: TENANT_B, name: "R", wsusGroup: "R", order: 0 } });

    const [me] = await prisma.$queryRaw<{ u: string; su: boolean }[]>`SELECT current_user AS u, rolsuper AS su FROM pg_roles WHERE rolname = current_user`;
    expect(me).toEqual({ u: APP_ROLE, su: false });
    expect(await prisma.ring.count()).toBe(0); // a forgotten scope leaks nothing
    expect(await withTenant(TENANT_A, (tx) => tx.ring.findMany({ select: { tenantId: true } }))).toEqual([{ tenantId: TENANT_A }]);
    expect(await withPlatform((tx) => tx.ring.count())).toBe(2);
    await expect(
      withTenant(TENANT_A, (tx) => tx.ring.create({ data: { tenantId: TENANT_B, name: "X", wsusGroup: "X", order: 1 } })),
    ).rejects.toThrow(/row-level security/);
    // writes outside any scope are refused as well
    await expect(prisma.ring.create({ data: { tenantId: TENANT_A, name: "Y", wsusGroup: "Y", order: 2 } })).rejects.toThrow(/row-level security/);
  });
});

describe("audit under RLS", () => {
  it("appends from unscoped transactions land in the right chain and verify", async () => {
    await appendAudit({ actor: "system:fetcher", action: "test.platform", entity: "T", entityId: "1" });
    // what fetch / auth / admin code does: a plain transaction, then appendAudit(…, tx)
    await prisma.$transaction(async (tx) => {
      await tx.fetchRun.create({ data: { source: "test" } });
      await appendAudit({ actor: "system:fetcher", action: "test.platform_tx", entity: "T", entityId: "2" }, tx);
    });
    await prisma.$transaction((tx) => appendAudit({ tenantId: TENANT_A, actor: "u@a", action: "test.bank_tx", entity: "T", entityId: "3" }, tx));
    await appendAudit({ tenantId: TENANT_B, actor: "u@b", action: "test.bank", entity: "T", entityId: "4" });

    expect(await verifyAuditLog(null)).toMatchObject({ valid: true, count: 2 });
    expect(await verifyAuditLog(TENANT_A)).toMatchObject({ valid: true, count: 1 });
    expect(await verifyAuditLog(TENANT_B)).toMatchObject({ valid: true, count: 1 });
    expect((await auditExportStatus(null)).pending).toBe(2);
    const chains = await admin.auditEvent.findMany({ orderBy: { seq: "asc" }, select: { action: true, tenantId: true } });
    expect(chains).toEqual([
      { action: "test.platform", tenantId: null },
      { action: "test.platform_tx", tenantId: null },
      { action: "test.bank_tx", tenantId: TENANT_A },
      { action: "test.bank", tenantId: TENANT_B },
    ]);
  });

  it("a fetcher trust decision (plain transaction + audit) works and goes to the platform chain", async () => {
    const rel = await admin.mirroredRelease.create({
      data: {
        component: "TACTICAL_AGENT", version: "2.12.0", assetName: "tacticalagent-v2.12.0-windows-amd64.exe",
        sourceUrl: "https://github.com/x", sha256: "a".repeat(64), sizeBytes: BigInt(1), repoPath: "tactical/agent/2.12.0/x.exe", verification: "PENDING",
      },
    });
    await decideMirror(rel.id, false, "admin@pg");
    expect((await admin.mirroredRelease.findUniqueOrThrow({ where: { id: rel.id } })).verification).toBe("REJECTED");
    const ev = await admin.auditEvent.findFirstOrThrow({ where: { action: "mirror.reject" } });
    expect(ev.tenantId).toBeNull();
    expect((await verifyAuditLog(null)).valid).toBe(true);
  });
});

describe("worker tick under RLS", () => {
  async function approvedChangeRequest() {
    const maker = asSessionUser(await admin.user.create({ data: { upn: "op@pg", name: "Op", role: "OPERATOR" } }));
    const checker = asSessionUser(await admin.user.create({ data: { upn: "ap@a", name: "Ap", role: "APPROVER", tenantId: TENANT_A } }));
    const ring = await admin.ring.create({ data: { tenantId: TENANT_A, name: "R0", wsusGroup: "R0", order: 0 } });
    const ep = await admin.endpoint.create({ data: { tenantId: TENANT_A, tacticalAgentId: "agentAppRole01", hostname: "PC", ringId: ring.id } });
    const patch = await admin.patch.create({ data: { kind: "WINDOWS", externalId: GUID, kb: "KB3", title: "KB3", severity: "CRITICAL" } });
    const cr = await createChangeRequest(maker, TENANT_A, { title: "x", ringId: ring.id, patchIds: [patch.id] });
    await applyAction(maker, TENANT_A, cr.id, "submit");
    await applyAction(checker, TENANT_A, cr.id, "approve");
    await startDeployment(checker, TENANT_A, cr.id);
    return { cr, ep };
  }

  it("deploys, confirms, finalises and exports every chain", async () => {
    const { cr, ep } = await approvedChangeRequest();
    const siem = memorySiem();
    let installed = false;
    const t = fakeTactical(() => installed);

    const first = await runWorkerTick({ tactical: t, siem });
    expect(first.ok).toBe(true);
    expect(first.pushed).toBe(1);
    expect((await admin.deployment.findFirstOrThrow({ where: { endpointId: ep.id } })).status).toBe("SENT");
    expect(siem.lines.some((l) => l.includes(`chain="${TENANT_A}"`))).toBe(true);

    installed = true;
    const second = await runWorkerTick({ tactical: t, siem });
    expect(second.ok).toBe(true);
    expect((await admin.changeRequest.findUniqueOrThrow({ where: { id: cr.id } })).status).toBe("COMPLETED");
    expect(await verifyAuditLog(TENANT_A)).toMatchObject({ valid: true, anchorsChecked: expect.any(Number) });
    expect((await auditExportStatus(TENANT_A)).pending).toBe(0);
  });

  it("scan ingestion + discovery rebuild work for the legacy bank", async () => {
    await admin.endpoint.create({ data: { tenantId: TENANT_A, tacticalAgentId: "agentAppRole02", hostname: "PC2" } });
    const r = await ingestDueEndpoints(fakeTactical(() => false));
    expect(r).toMatchObject({ ingested: 1, discovery: { products: 1 } });
    expect(await admin.endpointPatchState.count({ where: { tenantId: TENANT_A } })).toBe(1);
  });

  it("a failing step is reported but never stops the others (still a normal result, ok=false)", async () => {
    const { ep } = await approvedChangeRequest();
    const r = await runWorkerTick({ tactical: fakeTactical(() => false), siem: memorySiem(true) });
    expect(r.ok).toBe(false);
    expect(r.steps.siemBefore).toMatch(/^FAILED: SIEM unreachable/);
    expect(r.steps.siemAfter).toMatch(/^FAILED/);
    expect(r.steps.deployQueue).toBe("pushed 1");
    expect(r.steps.finalise).toBe("ok");
    expect((await admin.deployment.findFirstOrThrow({ where: { endpointId: ep.id } })).status).toBe("SENT");
  });

  it("an extra step that throws is isolated too", async () => {
    const r = await runWorkerTick({
      tactical: fakeTactical(() => false),
      siem: null,
      extraSteps: [
        { name: "boom", run: async () => { throw new Error("kaput"); } },
        { name: "fine", run: async () => undefined },
      ],
    });
    expect(r.ok).toBe(false);
    expect(r.steps).toMatchObject({ boom: "FAILED: kaput", fine: "ok", siemBefore: "not configured", deployQueue: "pushed 0" });
  });
});

describe("site install, enrolment and webhook encryption under RLS", () => {
  it("bundle access (code lookup, audit) and post-enrolment CACHE_PACKAGE work as the runtime role", async () => {
    const platformAdmin = asSessionUser(await admin.user.create({ data: { upn: "padmin@pg", name: "P", role: "ADMIN" } }));
    const agent = await admin.mirroredRelease.create({
      data: {
        component: "TACTICAL_AGENT",
        version: "2.12.0",
        assetName: "tacticalagent-v2.12.0-windows-amd64.exe",
        sourceUrl: "https://github.com/x",
        sha256: "e".repeat(64),
        sizeBytes: BigInt(10),
        repoPath: "tactical/agent/2.12.0/tacticalagent-v2.12.0-windows-amd64.exe",
        verification: "VERIFIED",
      },
    });
    const { code } = await createEnrollmentCode(platformAdmin, { tenantId: TENANT_A, name: "Site 1" });

    const ok = await authorizeBundleAccess(`PatchGate-Enrolment ${code}`, "192.0.2.10");
    expect(ok).toMatchObject({ ok: true, grant: { tenantId: TENANT_A, siteName: "Site 1" } });
    if (!ok.ok) throw new Error("unreachable");
    await auditBundleDownload(ok.grant, { version: "1.0", file: "patchgate-site-1.0.tar.gz", ip: "192.0.2.10", range: null, size: 1 });
    expect(await admin.auditEvent.count({ where: { tenantId: TENANT_A, action: "connector.bundle_downloaded" } })).toBe(1);
    expect(await authorizeBundleAccess("PatchGate-Enrolment ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ", "192.0.2.11")).toEqual({ ok: false, status: 403 });

    const r = await redeemEnrollment(enrollBody(code, makeConnectorKey()));
    const jobs = await admin.connectorJob.findMany({ where: { connectorId: r.connectorId, type: "CACHE_PACKAGE" } });
    expect(jobs.map((j) => (j.payload as { package: { sha256: string } }).package.sha256)).toEqual([agent.sha256]);
    // the code is consumed by the enrolment → no more bundle access
    expect(await authorizeBundleAccess(`PatchGate-Enrolment ${code}`, "192.0.2.12")).toEqual({ ok: false, status: 403 });
  });

  it("webhook URLs are stored sealed; legacy plaintext rows are drained by the worker step", async () => {
    const bankAdmin = asSessionUser(await admin.user.create({ data: { upn: "badmin@a", name: "B", role: "ADMIN", tenantId: TENANT_A } }));
    const url = "https://hooks.approle.example/services/T/B/secretTokenAppRole";
    await updateNotificationSettings(bankAdmin, TENANT_A, { action: "add-webhook", url });
    const row = await admin.notificationSetting.findUniqueOrThrow({ where: { scope: TENANT_A } });
    expect(row.webhookUrlsLegacy).toEqual([]);
    expect(row.webhookUrlsEnc).toHaveLength(1);
    expect(row.webhookUrlsEnc[0]).not.toContain("secretTokenAppRole");

    // a row from before the migration (plaintext only)
    await admin.notificationSetting.create({ data: { scope: TENANT_B, tenantId: TENANT_B, webhookUrlsLegacy: ["https://hooks.approle.example/services/legacyBBBB"] } });
    expect(await drainLegacyWebhooks(authKeyring())).toBe(1);
    const drained = await admin.notificationSetting.findUniqueOrThrow({ where: { scope: TENANT_B } });
    expect(drained.webhookUrlsLegacy).toEqual([]);
    expect(drained.webhookUrlsEnc.join("")).not.toContain("legacy");
    expect(await drainLegacyWebhooks(authKeyring())).toBe(0);
    const bankB = asSessionUser(await admin.user.create({ data: { upn: "badmin@b", name: "B2", role: "ADMIN", tenantId: TENANT_B } }));
    expect((await getNotificationSettings(bankB, TENANT_B)).webhooks.map((w) => w.display)).toEqual(["https://hooks.approle.example/…BBBB"]);
  });
});
