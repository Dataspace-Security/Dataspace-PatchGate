import "server-only";
import { prisma } from "@/lib/db";
import { appendAudit } from "@/lib/audit/service";
import type { SessionUser } from "@/lib/auth/session";
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
 * "Bank approval required" cannot be turned off by anyone (platform rule: at least one approver from the
 * bank on every change request) — the schema accepts only `true` and the database CHECK refuses `false`.
 */
export async function updateBankPolicy(user: SessionUser, tenantId: string, raw: unknown): Promise<BankPolicy> {
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
