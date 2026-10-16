import "server-only";
import { prisma } from "@/lib/db";
import { log } from "@/lib/log";
import { auditAuth } from "@/lib/auth/audit";
import { revokeUserSessions } from "@/lib/auth/session-store";
import { authTx } from "@/lib/auth/tx";
import { withPlatform } from "@/lib/tenancy/db";
import { inactiveToDisable, type ActivityRow } from "./account-policy";
import { getSecurityPolicy } from "./security-store";

/**
 * Worker step: deactivate accounts without activity for SecurityPolicy.inactivityDisableDays (default 90).
 * Activity = last sign-in, account creation, use of a live session, or any administrator action on the
 * account (user.* audit event — e.g. a reactivation restarts the clock). Platform admins are included,
 * but at least one active platform admin always remains. Each deactivation revokes the user's sessions
 * and is audited (action user.deactivated_inactive) on the user's chain.
 */

const DAY_MS = 86_400_000;
const BATCH = 500;
// Same advisory lock as admin-service: serialises changes that must keep ≥ 1 active platform admin.
const ADMIN_LOCK_KEY = 4_242_017;

export interface InactivityResult {
  checked: number;
  disabled: number;
}

/** Users the audit chain shows an administrator acted on since `since` (they count as active). */
async function recentlyAdministered(ids: readonly string[], since: Date): Promise<Set<string>> {
  if (ids.length === 0) return new Set();
  const rows = await withPlatform((tx) =>
    tx.auditEvent.findMany({
      where: { entity: "User", entityId: { in: [...ids] }, action: { startsWith: "user." }, ts: { gte: since } },
      select: { entityId: true },
      distinct: ["entityId"],
    }),
  );
  return new Set(rows.map((r) => r.entityId));
}

export async function disableInactiveUsers(now = new Date()): Promise<InactivityResult> {
  const policy = await getSecurityPolicy();
  if (policy.inactivityDisableDays <= 0) return { checked: 0, disabled: 0 };
  const cutoff = new Date(now.getTime() - policy.inactivityDisableDays * DAY_MS);

  const stale = await prisma.user.findMany({
    where: {
      active: true,
      createdAt: { lt: cutoff },
      OR: [{ lastLoginAt: null }, { lastLoginAt: { lt: cutoff } }],
      sessions: { none: { lastSeenAt: { gte: cutoff } } },
    },
    select: { id: true, upn: true, role: true, tenantId: true, createdAt: true, lastLoginAt: true },
    orderBy: { id: "asc" },
    take: BATCH,
  });
  const administered = await recentlyAdministered(stale.map((u) => u.id), cutoff);
  const rows: (ActivityRow & { upn: string })[] = stale
    .filter((u) => !administered.has(u.id))
    .map((u) => ({ id: u.id, upn: u.upn, role: u.role, tenantId: u.tenantId, lastActivityAt: u.lastLoginAt && u.lastLoginAt > u.createdAt ? u.lastLoginAt : u.createdAt }));
  if (rows.length === 0) return { checked: stale.length, disabled: 0 };

  let disabled = 0;
  for (const target of rows) {
    try {
      const done = await authTx(async (tx) => {
        await tx.$executeRaw`SELECT pg_advisory_xact_lock(${ADMIN_LOCK_KEY})`;
        if (target.tenantId === null && target.role === "ADMIN") {
          const admins = await tx.user.count({ where: { role: "ADMIN", tenantId: null, active: true } });
          const staleAdmins = rows.filter((r) => r.tenantId === null && r.role === "ADMIN");
          if (!inactiveToDisable(staleAdmins, policy, now, admins).some((r) => r.id === target.id)) return false;
          const others = await tx.user.count({ where: { role: "ADMIN", tenantId: null, active: true, id: { not: target.id } } });
          if (others === 0) return false; // never leave the platform without an administrator
        }
        const r = await tx.user.updateMany({ where: { id: target.id, active: true }, data: { active: false } });
        if (r.count !== 1) return false;
        const sessionsRevoked = await revokeUserSessions(tx, target.id);
        await auditAuth(
          {
            actor: "system",
            action: "user.deactivated_inactive",
            entity: "User",
            entityId: target.id,
            payload: { upn: target.upn, lastActivityAt: target.lastActivityAt.toISOString(), inactivityDays: policy.inactivityDisableDays, sessionsRevoked },
            tenantId: target.tenantId,
          },
          tx,
        );
        return true;
      });
      if (done) disabled++;
    } catch (err: unknown) {
      log.error("policy.inactivity_disable_failed", { userId: target.id, err });
    }
  }
  if (disabled > 0) log.warn("policy.inactive_users_disabled", { disabled, inactivityDays: policy.inactivityDisableDays });
  return { checked: stale.length, disabled };
}
