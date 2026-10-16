import "server-only";
import { connection } from "next/server";
import { cookies } from "next/headers";
import { prisma } from "@/lib/db";
import { authMode, env } from "@/lib/env";
import { sessionIsLive, shouldTouch } from "./claims";
import { SESSION_COOKIE, sha256Hex } from "./tokens";
import type { Actor } from "@/lib/approvals/state-machine";

export class AuthError extends Error {
  constructor(
    message: string,
    readonly status: 401 | 403,
  ) {
    super(message);
    this.name = "AuthError";
  }
}

export interface SessionUser extends Actor {
  upn: string;
  name: string;
  /** null = our team (platform staff, may act for any bank); otherwise the user's own bank. */
  tenantId: string | null;
}

export const DEV_USER_COOKIE = "pg_dev_user";

/**
 * Resolve the current user.
 * - AUTH_MODE local (production default: password + TOTP) or oidc (bank SSO): server-side session
 *   from the opaque session cookie, with idle + absolute expiry and the user / bank kill switches.
 * - AUTH_MODE dev (development only): the dev identity (cookie from /dev-login, else DEV_USER_UPN).
 */
export async function getCurrentUser(): Promise<SessionUser> {
  // Identity is per-request: never let a route that calls this be prerendered/cached.
  await connection();
  const e = env();
  if (authMode(e) !== "dev") return userFromSession(e.SESSION_IDLE_MINUTES);
  if (e.NODE_ENV !== "development") throw new AuthError("Not signed in", 401); // env.ts forbids this already

  const upn = (await cookies()).get(DEV_USER_COOKIE)?.value ?? e.DEV_USER_UPN;
  if (!upn) throw new AuthError("Not signed in", 401);
  const user = await prisma.user.findUnique({ where: { upn }, include: { tenant: { select: { active: true } } } });
  if (!user || !user.active || user.tenant?.active === false) throw new AuthError("Unknown or disabled user", 401);
  return { id: user.id, role: user.role, upn: user.upn, name: user.name, tenantId: user.tenantId };
}

async function userFromSession(idleMinutes: number): Promise<SessionUser> {
  const token = (await cookies()).get(SESSION_COOKIE)?.value;
  if (!token) throw new AuthError("Not signed in", 401);
  const id = sha256Hex(token);
  const s = await prisma.session.findUnique({ where: { id }, include: { user: { include: { tenant: { select: { active: true } } } } } });
  const now = new Date();
  if (!s || !sessionIsLive(s, now, idleMinutes)) {
    if (s) await prisma.session.deleteMany({ where: { id } });
    throw new AuthError("Session expired", 401);
  }
  if (!s.user.active || s.user.tenant?.active === false) {
    await prisma.session.deleteMany({ where: { userId: s.userId } });
    throw new AuthError("Account deactivated", 401);
  }
  if (shouldTouch(s.lastSeenAt, now)) await prisma.session.updateMany({ where: { id }, data: { lastSeenAt: now } });
  return { id: s.user.id, role: s.user.role, upn: s.user.upn, name: s.user.name, tenantId: s.user.tenantId };
}

export function requireRole(user: SessionUser, roles: readonly Actor["role"][]): void {
  if (!roles.includes(user.role)) throw new AuthError("Insufficient role", 403);
}

/**
 * CSRF defence for cookie-authenticated mutations: the browser-sent Origin must match Host.
 * Machine-to-machine routes (worker, WSUS) use tokens instead and don't call this.
 */
export function requireSameOrigin(req: Request): void {
  const origin = req.headers.get("origin");
  const host = req.headers.get("x-forwarded-host") ?? req.headers.get("host");
  if (!origin || !host) throw new AuthError("Missing origin", 403);
  let originHost: string;
  try {
    originHost = new URL(origin).host;
  } catch {
    throw new AuthError("Bad origin", 403);
  }
  if (originHost !== host) throw new AuthError("Cross-site request blocked", 403);
}
