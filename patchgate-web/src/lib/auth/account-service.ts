import "server-only";
import { prisma } from "@/lib/db";
import { auditAuth } from "./audit";
import { checkNewPassword, SAME_PASSWORD, type ChangeOwnPasswordInput } from "./account-policy";
import { registerFailure } from "./local-login";
import { isLocked, LOCKOUT_MINUTES } from "./lockout";
import { dummyPasswordHash, hashPassword, verifyPassword } from "./password";
import { revokeUserSessions, type ClientMeta } from "./session-store";
import { authTx } from "./tx";

/**
 * Self-service account actions for a signed-in local user (/account): change own password, sign out
 * every other session. The caller has already validated the session (getCurrentUser); `sessionId` is the
 * SHA-256 of the session cookie and is re-checked here so the "current" session is never someone else's.
 */

export interface AccountContext {
  userId: string;
  sessionId: string;
}

export type AccountResult<T> = { ok: true; data: T } | { ok: false; status: 400 | 401 | 403 | 409; error: string; signedOut?: boolean };

export const WRONG_CURRENT = "Your current password is incorrect.";
export const LOCKED_OUT = `Too many failed attempts: your account is locked for ${LOCKOUT_MINUTES} minutes and you have been signed out.`;
export const ACCOUNT_LOCKED = "Your account is temporarily locked after failed attempts. Try again later.";

const failure = (status: 400 | 401 | 403 | 409, error: string, signedOut = false): AccountResult<never> => ({ ok: false, status, error, signedOut });

async function loadOwnSession(ctx: AccountContext) {
  const session = await prisma.session.findFirst({ where: { id: ctx.sessionId, userId: ctx.userId }, select: { id: true } });
  if (!session) return null;
  const user = await prisma.user.findUnique({ where: { id: ctx.userId } });
  return user && user.active ? user : null;
}

export async function changeOwnPassword(
  ctx: AccountContext,
  input: ChangeOwnPasswordInput,
  meta: ClientMeta,
  now = new Date(),
): Promise<AccountResult<{ revokedSessions: number }>> {
  const user = await loadOwnSession(ctx);
  if (!user) return failure(401, "Not signed in", true);
  if (!user.passwordHash) return failure(400, "This account has no PatchGate password (it signs in through single sign-on).");
  if (isLocked(user.lockedUntil, now)) {
    await verifyPassword(input.currentPassword, await dummyPasswordHash()); // same cost either way
    return failure(403, ACCOUNT_LOCKED);
  }

  // Constant-time scrypt verify; a wrong answer counts toward the lockout exactly like a failed sign-in.
  if (!(await verifyPassword(input.currentPassword, user.passwordHash))) {
    const locked = await registerFailure(user, "wrong current password (self-service password change)", meta, now);
    if (locked) {
      // Five wrong answers from inside a session: treat the session as compromised.
      await authTx((tx) => revokeUserSessions(tx, user.id));
      return failure(401, LOCKED_OUT, true);
    }
    return failure(400, WRONG_CURRENT);
  }

  const rules = checkNewPassword(input, user.upn);
  if (!rules.ok) return failure(400, rules.reason);
  if (await verifyPassword(input.newPassword, user.passwordHash)) return failure(400, SAME_PASSWORD);

  const passwordHash = await hashPassword(input.newPassword);
  return authTx(async (tx) => {
    // Compare-and-set on the old hash: two concurrent changes cannot both win.
    const updated = await tx.user.updateMany({
      where: { id: user.id, passwordHash: user.passwordHash },
      data: { passwordHash, passwordChangedAt: now, mustChangePassword: false, failedLogins: 0, lockedUntil: null },
    });
    if (updated.count !== 1) return failure(409, "Your password was changed in the meantime. Reload the page and try again.");
    const revoked = await tx.session.deleteMany({ where: { userId: user.id, id: { not: ctx.sessionId } } });
    await tx.authChallenge.deleteMany({ where: { userId: user.id } });
    await auditAuth(
      {
        actor: user.upn,
        action: "auth.password_changed",
        entity: "User",
        entityId: user.id,
        payload: { forced: false, selfService: true, revokedSessions: revoked.count, ip: meta.ip },
        tenantId: user.tenantId,
      },
      tx,
    );
    return { ok: true, data: { revokedSessions: revoked.count } };
  });
}

/** Sign out everywhere else (keeps the current session), audited. */
export async function revokeOtherSessions(ctx: AccountContext, meta: ClientMeta): Promise<AccountResult<{ revokedSessions: number }>> {
  const user = await loadOwnSession(ctx);
  if (!user) return failure(401, "Not signed in", true);
  return authTx(async (tx) => {
    const revoked = await tx.session.deleteMany({ where: { userId: user.id, id: { not: ctx.sessionId } } });
    await auditAuth(
      { actor: user.upn, action: "auth.sessions_revoked", entity: "User", entityId: user.id, payload: { scope: "others", revokedSessions: revoked.count, ip: meta.ip }, tenantId: user.tenantId },
      tx,
    );
    return { ok: true, data: { revokedSessions: revoked.count } };
  });
}

export interface AccountSessionView {
  current: boolean;
  createdAt: Date;
  lastSeenAt: Date;
  ip: string | null;
  userAgent: string | null;
}

export interface AccountOverview {
  upn: string;
  name: string;
  role: string;
  bankName: string | null;
  lastLoginAt: Date | null;
  passwordChangedAt: Date | null;
  hasPassword: boolean;
  totpEnabled: boolean;
  sessions: AccountSessionView[];
}

/** What /account shows: live sessions only (absolute + idle limits). `sessionId` marks the current one (null in dev mode). */
export async function getAccountOverview(userId: string, sessionId: string | null, idleMinutes: number, now = new Date()): Promise<AccountOverview | null> {
  const idleCutoff = new Date(now.getTime() - idleMinutes * 60_000);
  const user = await prisma.user.findUnique({
    where: { id: userId },
    include: {
      tenant: { select: { name: true } },
      sessions: { where: { expiresAt: { gt: now }, lastSeenAt: { gt: idleCutoff } }, orderBy: { lastSeenAt: "desc" }, take: 20 },
    },
  });
  if (!user) return null;
  return {
    upn: user.upn,
    name: user.name,
    role: user.role,
    bankName: user.tenant?.name ?? null,
    lastLoginAt: user.lastLoginAt,
    passwordChangedAt: user.passwordChangedAt,
    hasPassword: user.passwordHash !== null,
    totpEnabled: user.totpEnabled,
    sessions: user.sessions.map((s) => ({ current: s.id === sessionId, createdAt: s.createdAt, lastSeenAt: s.lastSeenAt, ip: s.ip, userAgent: s.userAgent })),
  };
}
