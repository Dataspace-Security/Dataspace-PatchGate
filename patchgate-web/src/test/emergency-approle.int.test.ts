/**
 * Emergency changes, bank settings and account policies as a NON-owner, NON-superuser, NOBYPASSRLS role
 * (like production's patchgate_app): proves the new tables (ChangeRequestApproval with FORCED RLS + its
 * maker ≠ approver trigger, SecurityPolicy) and every new code path work with RLS actually applied.
 * Run: TEST_DATABASE_URL=postgresql://…/patchgate_test_auth INTEGRATION=1 npx vitest run src/test/emergency-approle.int.test.ts
 */
import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";
import { TENANT_A, TENANT_B, asSessionUser, configureTestEnv, resetDb } from "./helpers";

const APP_ROLE = "patchgate_app_test";
const APP_PASSWORD = "app-role-test-only-0123456789";

configureTestEnv({ AUTH_MODE: "local" });
vi.setConfig({ testTimeout: 300_000, hookTimeout: 120_000 });
const adminUrl = process.env.DATABASE_URL!;
const { PrismaClient } = await import("@prisma/client");
const admin = new PrismaClient({ datasourceUrl: adminUrl }); // superuser: fixtures + role setup only

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
const { createChangeRequest, applyAction } = await import("@/lib/approvals/service");
const { startDeployment } = await import("@/lib/deploy/start");
const { createRing, reorderRings, updateRing } = await import("@/lib/policies/rings");
const { createWindow } = await import("@/lib/policies/windows");
const { confirmBulkAssign, previewBulkAssign } = await import("@/lib/policies/bulk-assign");
const { updateBankPolicy } = await import("@/lib/policies/bank-settings");
const { updateSecurityPolicy } = await import("@/lib/policies/security-store");
const { disableInactiveUsers } = await import("@/lib/policies/inactivity");
const { createSession } = await import("@/lib/auth/session-store");
const { authTx } = await import("@/lib/auth/tx");

async function resetAll() {
  await admin.$executeRawUnsafe(`DELETE FROM "ChangeRequestApproval"`);
  await admin.$executeRawUnsafe(`DELETE FROM "SecurityPolicy"`);
  await resetDb(admin);
}

beforeEach(resetAll);
afterAll(async () => {
  await admin.$executeRawUnsafe(`DELETE FROM "SecurityPolicy"`);
  await prisma.$disconnect();
  await admin.$disconnect();
});

const mk = (upn: string, role: import("@/lib/auth/roles").Role, tenantId: string | null, extra: { createdAt?: Date; lastLoginAt?: Date } = {}) =>
  admin.user.create({ data: { upn, name: upn, role, tenantId, ...extra } }).then(asSessionUser);

describe("as the production-like runtime role", () => {
  it("bank settings: rings, windows, bulk assign, policy — RLS-scoped", async () => {
    const adminA = await mk("admin@a", "ADMIN", TENANT_A);
    await admin.endpoint.createMany({ data: [0, 1, 2].map((i) => ({ tenantId: TENANT_A, tacticalAgentId: `ag-${i}`, hostname: `BR-${i}`, site: "Pune" })) });
    await admin.endpoint.create({ data: { tenantId: TENANT_B, tacticalAgentId: "ag-b", hostname: "BR-9", site: "Pune" } });

    // Unscoped reads see nothing of the new tenant table (FORCED RLS)
    expect(await prisma.changeRequestApproval.count()).toBe(0);

    const r0 = await createRing(adminA, TENANT_A, { name: "Ring0-Test" });
    const r1 = await createRing(adminA, TENANT_A, { name: "Ring1-Pilot", rebootPolicy: "NEVER" });
    await reorderRings(adminA, TENANT_A, { ringIds: [r1.id, r0.id] });
    await updateRing(adminA, TENANT_A, r0.id, { name: "Ring0-Lab" });
    await createWindow(adminA, TENANT_A, { name: "Sunday", ringId: r0.id, cron: "0 2 * * 0", durationMin: 120, timezone: "Asia/Kolkata" });
    const prev = await previewBulkAssign(TENANT_A, { site: "Pune" });
    expect(prev.count).toBe(3); // bank B's PC in the same-named site is invisible
    expect((await confirmBulkAssign(adminA, TENANT_A, { filter: { site: "Pune" }, ringId: r0.id, expectedCount: 3 })).moved).toBe(3);
    await updateBankPolicy(adminA, TENANT_A, { maxTargetsPerCr: 2, approvalExpiryDays: 7 });
    // ring of bank A is not found from bank B's scope
    await expect(updateRing({ ...adminA, tenantId: TENANT_B }, TENANT_B, r0.id, { name: "x-ring" })).rejects.toThrow(/not found/i);
  });

  it("emergency: two distinct approvers, maker refused by the trigger, double deploy-now bypass, deploy", async () => {
    const maker = await mk("maker@pg", "ADMIN", null);
    const c1 = await mk("c1@a", "ADMIN", TENANT_A);
    const c2 = await mk("c2@a", "ADMIN", TENANT_A);
    const ring = await admin.ring.create({ data: { tenantId: TENANT_A, name: "Ring0-Test", wsusGroup: "Ring0-Test", order: 0 } });
    const win = await admin.maintenanceWindow.create({ data: { tenantId: TENANT_A, ringId: ring.id, name: "Yearly", cron: "0 3 1 1 *", durationMin: 60, timezone: "UTC" } });
    await admin.endpoint.create({ data: { tenantId: TENANT_A, tacticalAgentId: "ag-1", hostname: "PC-1", ringId: ring.id } });
    const patch = await admin.patch.create({ data: { kind: "WINDOWS", externalId: "22222222-2222-2222-2222-222222222222", title: "KB2", kb: "KB2" } });

    const cr = await createChangeRequest(maker, TENANT_A, { title: "Emergency", ringId: ring.id, windowId: win.id, patchIds: [patch.id], emergency: true, emergencyReason: "wormable vulnerability" });
    await applyAction(maker, TENANT_A, cr.id, "submit");
    await expect(
      withTenant(TENANT_A, (tx) => tx.changeRequestApproval.create({ data: { tenantId: TENANT_A, changeRequestId: cr.id, userId: maker.id, userUpn: maker.upn, userName: "m" } })),
    ).rejects.toThrow(/maker-checker/i);
    // A row for bank A cannot be written from bank B's scope (RLS WITH CHECK)
    await expect(
      withTenant(TENANT_B, (tx) => tx.changeRequestApproval.create({ data: { tenantId: TENANT_A, changeRequestId: cr.id, userId: c1.id, userUpn: c1.upn, userName: "c1" } })),
    ).rejects.toThrow();

    expect((await applyAction(c1, TENANT_A, cr.id, "approve", undefined, { deployNow: true })).status).toBe("PENDING_APPROVAL");
    const done = await applyAction(c2, TENANT_A, cr.id, "approve", undefined, { deployNow: true });
    expect(done).toMatchObject({ status: "APPROVED", windowBypass: true });
    expect(await withTenant(TENANT_B, (tx) => tx.changeRequestApproval.count())).toBe(0);
    expect(await withTenant(TENANT_A, (tx) => tx.changeRequestApproval.count())).toBe(2);
    expect((await startDeployment(maker, TENANT_A, cr.id)).status).toBe("DEPLOYING");
  });

  it("account policies: policy update, session cap, inactivity disable", async () => {
    const root = await mk("root@pg", "ADMIN", null);
    await mk("root2@pg", "ADMIN", null);
    const long = new Date(Date.now() - 400 * 86_400_000);
    const idle = await mk("idle@a", "ADMIN", TENANT_A, { createdAt: long, lastLoginAt: long });
    await updateSecurityPolicy(root, { maxSessionsPerUser: 1 });
    const u = await mk("bob@a", "ADMIN", TENANT_A);
    await authTx((tx) => createSession(tx, { userId: u.id, now: new Date(Date.now() - 1000), meta: { ip: null, userAgent: null } }));
    await authTx((tx) => createSession(tx, { userId: u.id, now: new Date(), meta: { ip: null, userAgent: null } }));
    expect(await admin.session.count({ where: { userId: u.id } })).toBe(1);
    expect((await disableInactiveUsers()).disabled).toBe(1);
    expect((await admin.user.findUniqueOrThrow({ where: { id: idle.id } })).active).toBe(false);
  });
});
