import { authTx } from "./tx";
import "server-only";
import type { Prisma } from "@prisma/client";
import { prisma } from "@/lib/db";
import { env } from "@/lib/env";
import { sessionsOverCap } from "@/lib/policies/account-policy";
import { getSecurityPolicy } from "@/lib/policies/security-store";
import { auditAuth } from "./audit";
import { randomToken, sha256Hex } from "./tokens";

type Tx = Prisma.TransactionClient;

export interface ClientMeta {
  ip: string | null;
  userAgent: string | null;
}

export interface NewSession {
  userId: string;
  now: Date;
  meta: ClientMeta;
  /** OIDC only: id_token_hint for IdP single sign-out. */
  idToken?: string | null;
}

/**
 * Issue a server-side session (same table, cookie and limits for local and SSO logins).
 * The browser gets the random token; the DB stores only its SHA-256. Absolute cap SESSION_MAX_HOURS,
 * idle timeout SESSION_IDLE_MINUTES (enforced in getCurrentUser).
 */
export async function createSession(tx: Tx, s: NewSession): Promise<string> {
  const token = randomToken();
  const id = sha256Hex(token);
  await tx.session.create({
    data: {
      id,
      userId: s.userId,
      createdAt: s.now,
      lastSeenAt: s.now,
      expiresAt: new Date(s.now.getTime() + env().SESSION_MAX_HOURS * 3_600_000),
      idToken: s.idToken ?? null,
      ip: s.meta.ip?.slice(0, 64) ?? null,
      userAgent: s.meta.userAgent?.slice(0, 300) ?? null,
    },
  });
  await enforceSessionCap(tx, s.userId, id, s.now);
  return token;
}

/**
 * Platform policy maxSessionsPerUser: after a new sign-in, revoke the user's OLDEST live sessions beyond
 * the cap (the new one always survives). Audited (auth.sessions_revoked) on the user's chain.
 */
async function enforceSessionCap(tx: Tx, userId: string, newSessionId: string, now: Date): Promise<void> {
  const { maxSessionsPerUser } = await getSecurityPolicy(tx);
  if (maxSessionsPerUser <= 0) return;
  const others = await tx.session.findMany({ where: { userId, id: { not: newSessionId }, expiresAt: { gt: now } }, select: { id: true, createdAt: true } });
  const revoke = sessionsOverCap(others, maxSessionsPerUser - 1);
  if (revoke.length === 0) return;
  await tx.session.deleteMany({ where: { userId, id: { in: revoke.map((r) => r.id) } } });
  const user = await tx.user.findUnique({ where: { id: userId }, select: { upn: true, tenantId: true } });
  if (!user) return;
  await auditAuth(
    { actor: user.upn, action: "auth.sessions_revoked", entity: "User", entityId: userId, payload: { reason: "session_cap", revoked: revoke.length, maxSessionsPerUser }, tenantId: user.tenantId },
    tx,
  );
}

/** Kill every session and pending sign-in of a user (deactivation, password reset). */
export async function revokeUserSessions(tx: Tx, userId: string): Promise<number> {
  const r = await tx.session.deleteMany({ where: { userId } });
  await tx.authChallenge.deleteMany({ where: { userId } });
  return r.count;
}

export interface EndedSession {
  userId: string;
  idToken: string | null;
}

/** Sign out: delete the session and audit it. Returns null when there was no live session. */
export async function endSession(sessionToken: string | undefined): Promise<EndedSession | null> {
  if (!sessionToken) return null;
  const s = await prisma.session.findUnique({ where: { id: sha256Hex(sessionToken) }, include: { user: true } });
  if (!s) return null;
  await authTx(async (tx) => {
    await tx.session.deleteMany({ where: { id: s.id } });
    await auditAuth({ actor: s.user.upn, action: "auth.logout", entity: "User", entityId: s.userId, payload: {}, tenantId: s.user.tenantId }, tx);
  });
  return { userId: s.userId, idToken: s.idToken };
}
