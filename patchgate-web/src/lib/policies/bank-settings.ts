import "server-only";
import { prisma } from "@/lib/db";
import { appendAudit } from "@/lib/audit/service";
import { canWrite } from "@/lib/auth/roles";
import { AuthError, type SessionUser } from "@/lib/auth/session";
import { enqueueNotification } from "@/lib/notify/enqueue";
import { canActForTenant } from "@/lib/tenancy/policy";
import { DomainError } from "@/lib/errors";
import { withTenant } from "@/lib/tenancy";
import { bankPolicySchema, type BankPolicy } from "./approval-policy";

const POLICY_SELECT = { requireBankApproval: true, approvalExpiryDays: true, maxTargetsPerCr: true, defaultRebootPolicy: true, timezone: true } as const;

export async function getBankPolicy(tenantId: string): Promise<BankPolicy> {
  const t = await prisma.tenant.findUnique({ where: { id: tenantId }, select: POLICY_SELECT });
  if (!t) throw new DomainError("Bank not found", 404);
  return t;
}

/**
 * Update the bank's approval policy / change defaults (audited on the BANK chain: bank_policy.updated).
 * "Approval required" (requireBankApproval) may be switched only by an ADMIN — the bank's own admin or a
 * platform admin (auditors never). A switch is audited separately (bank_policy.approval_switched, with the
 * consequence) and notifies the bank's and the platform's admins (APPROVAL_SETTING_CHANGED, critical).
 */
export async function updateBankPolicy(user: SessionUser, tenantId: string, raw: unknown): Promise<BankPolicy> {
  if (!canWrite(user)) throw new AuthError("Bank settings are for administrators only", 403);
  if (!canActForTenant(user, tenantId)) throw new AuthError("Not allowed for this bank", 403);
  const input = bankPolicySchema.parse(raw);
  return withTenant(tenantId, async (tx) => {
    await tx.$executeRaw`SELECT 1 FROM "Tenant" WHERE "id" = ${tenantId} FOR UPDATE`;
    const before = await tx.tenant.findUnique({ where: { id: tenantId }, select: POLICY_SELECT });
    if (!before) throw new DomainError("Bank not found", 404);
    const after = await tx.tenant.update({ where: { id: tenantId }, data: input, select: POLICY_SELECT });
    const changes = Object.fromEntries(
      (Object.keys(input) as (keyof BankPolicy)[]).filter((k) => before[k] !== after[k]).map((k) => [k, { from: before[k], to: after[k] }]),
    );
    await appendAudit(
      { tenantId, actor: user.upn, action: "bank_policy.updated", entity: "Tenant", entityId: tenantId, payload: { changes, actorBank: user.tenantId ?? "platform" } },
      tx,
    );
    if (before.requireBankApproval !== after.requireBankApproval) {
      await appendAudit(
        {
          tenantId,
          actor: user.upn,
          action: "bank_policy.approval_switched",
          entity: "Tenant",
          entityId: tenantId,
          payload: {
            approvalRequired: after.requireBankApproval,
            consequence: after.requireBankApproval
              ? "a bank admin other than the maker must approve every change request"
              : "change requests are approved on submit and can be deployed without a second person",
            actorBank: user.tenantId ?? "platform",
          },
        },
        tx,
      );
      await enqueueNotification(tx, { event: "APPROVAL_SETTING_CHANGED", tenantId, approvalRequired: after.requireBankApproval, actor: user.upn });
    }
    return after;
  });
}

/** Reboot defaults for the change-request form: bank default + per-ring overrides. */
export async function rebootDefaults(tenantId: string) {
  const [bank, rings] = await Promise.all([
    getBankPolicy(tenantId),
    withTenant(tenantId, (tx) => tx.ring.findMany({ where: { tenantId }, select: { id: true, rebootPolicy: true } })),
  ]);
  return { bankDefault: bank.defaultRebootPolicy, rings: Object.fromEntries(rings.map((r) => [r.id, r.rebootPolicy ?? bank.defaultRebootPolicy])) };
}
