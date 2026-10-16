import { z } from "zod";
import type { Role } from "@/lib/auth/roles";

/**
 * Platform-wide account security policy (pure rules). Persistence: security-store.ts; enforcement:
 * local sign-in (password max age), session-store (session cap), inactivity worker step (inactivity.ts).
 */

export interface SecurityPolicyValues {
  /** Password older than this forces a change at the next sign-in (0 = off) */
  passwordMaxAgeDays: number;
  /** Users without activity for this long are deactivated (0 = off) */
  inactivityDisableDays: number;
  /** Concurrent sessions per user, oldest revoked first (0 = unlimited) */
  maxSessionsPerUser: number;
}

export const DEFAULT_SECURITY_POLICY: SecurityPolicyValues = Object.freeze({
  passwordMaxAgeDays: 0,
  inactivityDisableDays: 90,
  maxSessionsPerUser: 0,
});

export const securityPolicySchema = z
  .object({
    passwordMaxAgeDays: z.coerce.number().int().min(0).max(3650),
    inactivityDisableDays: z.union([z.literal(0), z.coerce.number().int().min(7).max(3650)]),
    maxSessionsPerUser: z.coerce.number().int().min(0).max(100),
  })
  .partial()
  .refine((v) => Object.keys(v).length > 0, "nothing to change");
export type SecurityPolicyInput = z.infer<typeof securityPolicySchema>;

const DAY_MS = 86_400_000;

/** Has this user's local password outlived the max age? Users without a local password never expire. */
export function passwordExpired(
  user: { passwordHash: string | null; passwordChangedAt: Date | null; createdAt: Date },
  policy: Pick<SecurityPolicyValues, "passwordMaxAgeDays">,
  now: Date,
): boolean {
  if (policy.passwordMaxAgeDays <= 0 || !user.passwordHash) return false;
  const since = user.passwordChangedAt ?? user.createdAt;
  return now.getTime() - since.getTime() >= policy.passwordMaxAgeDays * DAY_MS;
}

/** Sessions to revoke so that only the newest `keep` remain (0 = revoke all). The caller applies "0 = unlimited". */
export function sessionsOverCap<T extends { id: string; createdAt: Date }>(sessions: readonly T[], keep: number): T[] {
  if (!Number.isInteger(keep) || keep < 0 || sessions.length <= keep) return [];
  const newestFirst = [...sessions].sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime() || b.id.localeCompare(a.id));
  return newestFirst.slice(keep);
}

export interface ActivityRow {
  id: string;
  role: Role;
  tenantId: string | null;
  /** Latest of: last sign-in, account creation, live session use, administrator action on the account */
  lastActivityAt: Date;
}

/**
 * Which active users to deactivate for inactivity. Platform admins are included, EXCEPT that at least one
 * active platform admin always remains (the most recently active one is kept when all would go).
 * `activePlatformAdmins` = how many active platform admins exist in total (candidates included).
 */
export function inactiveToDisable(rows: readonly ActivityRow[], policy: Pick<SecurityPolicyValues, "inactivityDisableDays">, now: Date, activePlatformAdmins: number): ActivityRow[] {
  if (policy.inactivityDisableDays <= 0) return [];
  const cutoff = now.getTime() - policy.inactivityDisableDays * DAY_MS;
  const stale = rows.filter((r) => r.lastActivityAt.getTime() < cutoff);
  const staleAdmins = stale.filter((r) => r.tenantId === null && r.role === "ADMIN");
  if (staleAdmins.length === 0 || staleAdmins.length < activePlatformAdmins) return stale;
  const keep = [...staleAdmins].sort((a, b) => b.lastActivityAt.getTime() - a.lastActivityAt.getTime())[0]!;
  return stale.filter((r) => r.id !== keep.id);
}
