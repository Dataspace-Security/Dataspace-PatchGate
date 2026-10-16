/**
 * Emergency changes + bank approval policy against a real PostgreSQL (RLS on, superuser login).
 * Run: TEST_DATABASE_URL=postgresql://…/patchgate_test_auth INTEGRATION=1 npx vitest run src/test/emergency.int.test.ts
 */
import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";
import { TENANT_A, asSessionUser, configureTestEnv, resetDb } from "./helpers";

configureTestEnv({ AUTH_MODE: "local" });
// Several approval rounds per test on the shared dev Postgres: allow for slow interactive transactions.
vi.setConfig({ testTimeout: 300_000, hookTimeout: 120_000 });

const { prisma } = await import("@/lib/db");
const { applyAction, createChangeRequest } = await import("@/lib/approvals/service");
const { updateDraftOptions } = await import("@/lib/approvals/emergency");
const { startDeployment } = await import("@/lib/deploy/start");
const { updateBankPolicy } = await import("@/lib/policies/bank-settings");
const { withTenant } = await import("@/lib/tenancy");
type SessionUser = import("@/lib/auth/session").SessionUser;

async function resetAll() {
  await prisma.$executeRawUnsafe(`DELETE FROM "ChangeRequestApproval"`);
  await resetDb(prisma);
}

interface Fixture {
  maker: SessionUser;
  bankApprover1: SessionUser;
  bankApprover2: SessionUser;
  platformApprover: SessionUser;
  platformApprover2: SessionUser;
  ringId: string;
  windowId: string;
  patchId: string;
}

async function user(upn: string, role: SessionUser["role"], tenantId: string | null): Promise<SessionUser> {
  return asSessionUser(await prisma.user.create({ data: { upn, name: upn.split("@")[0]!, role, tenantId } }));
}

async function fixture(endpoints = 3): Promise<Fixture> {
  const maker = await user("maker@platform.test", "ADMIN", null);
  const bankApprover1 = await user("checker1@bank-a.test", "ADMIN", TENANT_A);
  const bankApprover2 = await user("checker2@bank-a.test", "ADMIN", TENANT_A);
  const platformApprover = await user("approver@platform.test", "ADMIN", null);
  const platformApprover2 = await user("approver2@platform.test", "ADMIN", null);
  const { ringId, windowId } = await withTenant(TENANT_A, async (tx) => {
    const ring = await tx.ring.create({ data: { tenantId: TENANT_A, name: "Ring0-Test", wsusGroup: "Ring0-Test", order: 0, rebootPolicy: "NEVER" } });
    // A window that is never open now (Feb 30th does not exist → use a yearly one far away instead).
    const w = await tx.maintenanceWindow.create({ data: { tenantId: TENANT_A, ringId: ring.id, name: "Yearly", cron: "0 3 1 1 *", durationMin: 60, timezone: "UTC" } });
    for (let i = 0; i < endpoints; i++) {
      await tx.endpoint.create({ data: { tenantId: TENANT_A, tacticalAgentId: `agent-${i}`, hostname: `PC-${i}`, ringId: ring.id } });
    }
    return { ringId: ring.id, windowId: w.id };
  });
  const patch = await prisma.patch.create({ data: { kind: "WINDOWS", externalId: "11111111-1111-1111-1111-111111111111", title: "KB1 cumulative", kb: "KB1" } });
  return { maker, bankApprover1, bankApprover2, platformApprover, platformApprover2, ringId, windowId, patchId: patch.id };
}

async function emergencyCr(f: Fixture) {
  const cr = await createChangeRequest(f.maker, TENANT_A, {
    title: "Emergency KB1",
    ringId: f.ringId,
    windowId: f.windowId,
    patchIds: [f.patchId],
    emergency: true,
    emergencyReason: "Actively exploited remote code execution",
  });
  await applyAction(f.maker, TENANT_A, cr.id, "submit");
  return cr.id;
}

async function crRow(id: string) {
  return withTenant(TENANT_A, (tx) => tx.changeRequest.findFirstOrThrow({ where: { id }, include: { approvals: true } }));
}

async function actions(entityId: string): Promise<string[]> {
  const rows = await withTenant(TENANT_A, (tx) => tx.auditEvent.findMany({ where: { tenantId: TENANT_A, entityId }, orderBy: { seq: "asc" }, select: { action: true } }));
  return rows.map((r) => r.action);
}

beforeEach(resetAll);
afterAll(() => prisma.$disconnect());

describe("emergency change requests", () => {
  it("need TWO distinct approvers, neither the maker; separate audit actions", async () => {
    const f = await fixture();
    const id = await emergencyCr(f);
    const created = await crRow(id);
    expect(created).toMatchObject({ emergency: true, requiredApprovals: 2, status: "PENDING_APPROVAL", rebootPolicy: "NEVER" }); // ring override

    // The maker can never approve (state machine) …
    await expect(applyAction({ ...f.maker, role: "ADMIN" }, TENANT_A, id, "approve")).rejects.toThrow(/maker-checker/i);
    // … nor through a direct insert (DB trigger)
    await expect(
      withTenant(TENANT_A, (tx) =>
        tx.changeRequestApproval.create({ data: { tenantId: TENANT_A, changeRequestId: id, userId: f.maker.id, userUpn: f.maker.upn, userName: "m" } }),
      ),
    ).rejects.toThrow(/maker-checker/i);

    const first = await applyAction(f.bankApprover1, TENANT_A, id, "approve");
    expect(first).toMatchObject({ status: "PENDING_APPROVAL", approvals: 1 });
    await expect(applyAction(f.bankApprover1, TENANT_A, id, "approve")).rejects.toThrow(/different approver/i);
    expect((await crRow(id)).status).toBe("PENDING_APPROVAL");

    const second = await applyAction(f.bankApprover2, TENANT_A, id, "approve");
    expect(second).toMatchObject({ status: "APPROVED", approvals: 2, windowBypass: false });
    const row = await crRow(id);
    expect(row.approvedById).toBe(f.bankApprover2.id);
    expect(row.windowId).toBe(f.windowId); // no double "deploy now": window kept
    expect(row.approvalExpiresAt).not.toBeNull(); // default 14 days
    expect(await actions(id)).toEqual(
      expect.arrayContaining(["change_request.create", "change_request.emergency_marked", "change_request.emergency_submit", "change_request.emergency_approve"]),
    );
    expect(await actions(id)).not.toContain("change_request.emergency_window_bypass");
  });

  it("with bank approval required, two PLATFORM approvers never complete it; one bank approver does", async () => {
    const f = await fixture();
    const id = await emergencyCr(f);
    await applyAction(f.platformApprover, TENANT_A, id, "approve");
    await expect(applyAction(f.platformApprover2, TENANT_A, id, "approve")).rejects.toThrow(/at least one of the approvers must be from this bank/i);
    expect((await applyAction(f.bankApprover1, TENANT_A, id, "approve")).status).toBe("APPROVED");
  });

  it("bypasses the maintenance window ONLY when both approvers confirm deploy now", async () => {
    const f = await fixture();
    // one confirms, one does not → window kept
    const a = await emergencyCr(f);
    await applyAction(f.bankApprover1, TENANT_A, a, "approve", undefined, { deployNow: true });
    await applyAction(f.bankApprover2, TENANT_A, a, "approve", undefined, { deployNow: false });
    expect(await crRow(a)).toMatchObject({ windowBypass: false, windowId: f.windowId });

    // both confirm → window bypassed (cleared for the pipeline, original recorded) + its own audit event
    const b = await emergencyCr(f);
    await applyAction(f.bankApprover1, TENANT_A, b, "approve", undefined, { deployNow: true });
    const r = await applyAction(f.bankApprover2, TENANT_A, b, "approve", undefined, { deployNow: true });
    expect(r.windowBypass).toBe(true);
    expect(await crRow(b)).toMatchObject({ windowBypass: true, windowId: null, bypassedWindowId: f.windowId });
    expect(await actions(b)).toContain("change_request.emergency_window_bypass");

    // deploy now: queued immediately
    const d = await startDeployment(f.maker, TENANT_A, b);
    expect(d).toMatchObject({ status: "DEPLOYING", queued: 3 });
  });

  it("deploy now is refused on a normal request", async () => {
    const f = await fixture();
    const cr = await createChangeRequest(f.maker, TENANT_A, { title: "Normal KB1", ringId: f.ringId, patchIds: [f.patchId] });
    await applyAction(f.maker, TENANT_A, cr.id, "submit");
    await expect(applyAction(f.bankApprover1, TENANT_A, cr.id, "approve", undefined, { deployNow: true })).rejects.toThrow(/only emergency/i);
  });

  it("the maker marks a draft as emergency (reason required); others cannot", async () => {
    const f = await fixture();
    const cr = await createChangeRequest(f.maker, TENANT_A, { title: "Draft", ringId: f.ringId, patchIds: [f.patchId] });
    await expect(updateDraftOptions(f.maker, TENANT_A, cr.id, { emergency: true, emergencyReason: "short" })).rejects.toThrow();
    await expect(updateDraftOptions(f.bankApprover2, TENANT_A, cr.id, { emergency: true, emergencyReason: "bank admin tries this" })).rejects.toThrow(/only the creator/i);
    await updateDraftOptions(f.maker, TENANT_A, cr.id, { emergency: true, emergencyReason: "zero-day in the VPN client", rebootPolicy: "ALWAYS" });
    expect(await crRow(cr.id)).toMatchObject({ emergency: true, requiredApprovals: 2, rebootPolicy: "ALWAYS" });
    await applyAction(f.maker, TENANT_A, cr.id, "submit");
    await expect(updateDraftOptions(f.maker, TENANT_A, cr.id, { emergency: false })).rejects.toThrow(/draft/i);
    expect(await actions(cr.id)).toEqual(expect.arrayContaining(["change_request.emergency_marked", "change_request.options_updated"]));
  });
});

describe("bank approval policy", () => {
  it("requests above the target limit need a second approver", async () => {
    const f = await fixture(5);
    await updateBankPolicy(f.bankApprover2, TENANT_A, { maxTargetsPerCr: 4 });
    const cr = await createChangeRequest(f.maker, TENANT_A, { title: "Big", ringId: f.ringId, patchIds: [f.patchId] });
    await applyAction(f.maker, TENANT_A, cr.id, "submit");
    expect((await crRow(cr.id)).requiredApprovals).toBe(2);
    expect((await applyAction(f.bankApprover1, TENANT_A, cr.id, "approve")).status).toBe("PENDING_APPROVAL");
    expect((await applyAction(f.bankApprover2, TENANT_A, cr.id, "approve")).status).toBe("APPROVED");
  });

  it("an expired approval cannot be deployed", async () => {
    const f = await fixture();
    await updateBankPolicy(f.bankApprover2, TENANT_A, { approvalExpiryDays: 1 });
    const cr = await createChangeRequest(f.maker, TENANT_A, { title: "Expiring", ringId: f.ringId, patchIds: [f.patchId] });
    await applyAction(f.maker, TENANT_A, cr.id, "submit");
    await applyAction(f.bankApprover1, TENANT_A, cr.id, "approve");
    const row = await crRow(cr.id);
    expect(row.approvalExpiresAt!.getTime() - row.decidedAt!.getTime()).toBe(86_400_000);
    await withTenant(TENANT_A, (tx) => tx.changeRequest.updateMany({ where: { id: cr.id }, data: { approvalExpiresAt: new Date(Date.now() - 1000) } }));
    await expect(startDeployment(f.maker, TENANT_A, cr.id)).rejects.toThrow(/approval expired/i);
  });

  it("only an ADMIN (bank or platform) can switch approval; the switch is audited on the bank chain and notifies the admins", async () => {
    const f = await fixture();
    const platformAdmin = await user("root@platform.test", "ADMIN", null);
    const auditor = await user("auditor@bank-a.test", "AUDITOR", TENANT_A);
    await expect(updateBankPolicy(auditor, TENANT_A, { requireBankApproval: false })).rejects.toThrow(/administrators only/i);
    expect((await prisma.tenant.findUniqueOrThrow({ where: { id: TENANT_A } })).requireBankApproval).toBe(true); // default ON

    await updateBankPolicy(f.bankApprover2, TENANT_A, { requireBankApproval: false, defaultRebootPolicy: "ALWAYS" });
    expect(await prisma.tenant.findUniqueOrThrow({ where: { id: TENANT_A } })).toMatchObject({ requireBankApproval: false, defaultRebootPolicy: "ALWAYS" });
    expect(await actions(TENANT_A)).toEqual(expect.arrayContaining(["bank_policy.updated", "bank_policy.approval_switched"]));
    const notes = await prisma.notification.findMany({ where: { event: "APPROVAL_SETTING_CHANGED", tenantId: TENANT_A } });
    expect(notes.map((n) => n.target)).toEqual(expect.arrayContaining(["checker1@bank-a.test", "checker2@bank-a.test", "root@platform.test"]));
    expect(notes.map((n) => n.target)).not.toContain("auditor@bank-a.test");
    expect(notes[0]?.subject).toMatch(/approval switched OFF/i);

    await updateBankPolicy(platformAdmin, TENANT_A, { requireBankApproval: true });
    expect((await prisma.tenant.findUniqueOrThrow({ where: { id: TENANT_A } })).requireBankApproval).toBe(true);
    expect((await actions(TENANT_A)).filter((a) => a === "bank_policy.approval_switched")).toHaveLength(2);
  });

  it("approval OFF: an admin's request (even an emergency) is auto-approved on submit and deploys without a second person", async () => {
    const f = await fixture();
    await updateBankPolicy(f.bankApprover1, TENANT_A, { requireBankApproval: false });
    const cr = await createChangeRequest(f.maker, TENANT_A, {
      title: "No second person",
      ringId: f.ringId,
      patchIds: [f.patchId],
      emergency: true,
      emergencyReason: "Actively exploited remote code execution",
    });
    const r = await applyAction(f.maker, TENANT_A, cr.id, "submit");
    expect(r).toMatchObject({ status: "APPROVED", autoApproved: true, windowBypass: false });
    const row = await crRow(cr.id);
    expect(row).toMatchObject({ status: "APPROVED", autoApproved: true, approvedById: null, windowBypass: false, targetCount: 3 });
    expect(row.approvals).toHaveLength(0);
    expect(row.decidedAt).not.toBeNull();
    expect(await actions(cr.id)).toEqual(expect.arrayContaining(["change_request.emergency_submit", "change_request.approval_skipped"]));
    const skipped = await withTenant(TENANT_A, (tx) => tx.auditEvent.findFirstOrThrow({ where: { entityId: cr.id, action: "change_request.approval_skipped" } }));
    expect(skipped.tenantId).toBe(TENANT_A);
    expect(JSON.stringify(skipped.payload)).toMatch(/approval is off/i);

    await startDeployment(f.maker, TENANT_A, cr.id);
    expect((await crRow(cr.id)).status).toBe("DEPLOYING");

    // Switched back ON: the next request waits for a bank admin again.
    await updateBankPolicy(f.bankApprover1, TENANT_A, { requireBankApproval: true });
    const next = await createChangeRequest(f.maker, TENANT_A, { title: "Normal", ringId: f.ringId, patchIds: [f.patchId] });
    expect(await applyAction(f.maker, TENANT_A, next.id, "submit")).toMatchObject({ status: "PENDING_APPROVAL", autoApproved: false });
  });
});
