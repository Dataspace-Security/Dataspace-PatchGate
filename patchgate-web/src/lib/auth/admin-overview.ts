import "server-only";
import { withPlatform, withTenant, type Tx } from "@/lib/tenancy/db";

/** Audit actions shown on the administration overview. */
export const ADMIN_ACTIONS = [
  "user.created",
  "user.updated",
  "user.deactivated",
  "user.reactivated",
  "user.password_reset",
  "user.mfa_reset",
  "user.reset_denied",
  "user.unlocked",
  "tenant.created",
  "tenant.updated",
  "tenant.select",
  "auth.lockout",
  "auth.failed_unknown_summary",
];

/**
 * Recent administrative events for the overview. AuditEvent is under Row-Level Security (the production DB
 * role is not the owner), so it is read through an explicit scope: a platform admin (tenantId null) sees every
 * chain via withPlatform, a bank admin only their bank's chain via withTenant. A plain prisma query sees
 * nothing in production.
 */
export function recentAdminEvents(tenantId: string | null, take = 12) {
  const read = (tx: Tx) =>
    tx.auditEvent.findMany({
      where: { action: { in: ADMIN_ACTIONS }, ...(tenantId === null ? {} : { tenantId }) },
      orderBy: { seq: "desc" },
      take,
      select: { seq: true, ts: true, actor: true, action: true, payload: true, tenantId: true },
    });
  return tenantId === null ? withPlatform(read) : withTenant(tenantId, read);
}
