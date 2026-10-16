import "server-only";
import { withPlatform, withTenant } from "@/lib/tenancy/db";

/** Administrator credential resets that make the user's NEXT sign-in worth an alert. */
export const RESET_ACTIONS = ["user.password_reset", "user.mfa_reset"] as const;

export interface CredentialReset {
  action: string;
  actor: string;
  ts: Date;
}

/**
 * The most recent administrator reset of this user's password / authenticator since their last successful
 * sign-in (null if none). Read from the user's own audit chain (append-only, hash-chained) through an explicit
 * RLS scope, so the flag cannot be lost by editing the user row.
 */
export async function credentialResetSinceLastLogin(user: { id: string; tenantId: string | null; lastLoginAt: Date | null }): Promise<CredentialReset | null> {
  const read = (tx: Parameters<Parameters<typeof withPlatform>[0]>[0]) =>
    tx.auditEvent.findFirst({
      where: {
        tenantId: user.tenantId,
        entity: "User",
        entityId: user.id,
        action: { in: [...RESET_ACTIONS] },
        ...(user.lastLoginAt ? { ts: { gt: user.lastLoginAt } } : {}),
      },
      orderBy: { seq: "desc" },
      select: { action: true, actor: true, ts: true },
    });
  return user.tenantId ? withTenant(user.tenantId, read) : withPlatform(read);
}
