import { authTx } from "./tx";
import "server-only";
import * as client from "openid-client";
import { prisma } from "@/lib/db";
import { env } from "@/lib/env";
import { auditAuth } from "./audit";
import { flushUnknownLoginSummary } from "./unknown-login-summary";
import { describeError } from "@/lib/errors-describe";
import { parseRoleMap, roleFromClaims, safeReturnTo, stringClaim } from "./claims";
import { createSession, endSession, type ClientMeta } from "./session-store";
import { disableInactiveUsers } from "@/lib/policies/inactivity";
import { SESSION_COOKIE, randomToken, sha256Hex } from "./tokens";

/**
 * Bank SSO via OpenID Connect (authorization code + PKCE + state + nonce) using openid-client
 * (OpenID-certified). The IdP decides WHO (authentication + MFA) and WHICH ROLE (groups/app roles);
 * PatchGate keeps a local kill switch (User.active) and audits every login, denial and logout.
 */

export { SESSION_COOKIE, sha256Hex };
export const LOGIN_COOKIE = "__Host-pg_login";
export const LOGIN_TTL_MS = 10 * 60_000;
const CONFIG_TTL_MS = 60 * 60_000;


let cached: { at: number; config: Promise<client.Configuration> } | null = null;

/** Discovered IdP configuration (re-discovered hourly so key/endpoint rotation is picked up). */
export function oidcConfig(): Promise<client.Configuration> {
  if (cached && Date.now() - cached.at < CONFIG_TTL_MS) return cached.config;
  const e = env();
  const config = client
    .discovery(
      new URL(e.OIDC_ISSUER_URL!),
      e.OIDC_CLIENT_ID!,
      e.OIDC_CLIENT_SECRET ? { client_secret: e.OIDC_CLIENT_SECRET } : {},
      e.OIDC_CLIENT_SECRET ? client.ClientSecretPost(e.OIDC_CLIENT_SECRET) : client.None(),
      { timeout: 10 },
    )
    .catch((err: unknown) => {
      cached = null; // never cache a failure
      throw err;
    });
  cached = { at: Date.now(), config };
  return config;
}

/** Begin a login: persist PKCE/state/nonce server-side (single use) and return the IdP URL. */
export async function startLogin(returnTo: string | null): Promise<{ url: URL; loginCookie: string }> {
  const e = env();
  const config = await oidcConfig();
  const loginCookie = randomToken();
  const verifier = client.randomPKCECodeVerifier();
  const state = client.randomState();
  const nonce = client.randomNonce();
  const now = new Date();
  await prisma.oidcLogin.deleteMany({ where: { expiresAt: { lt: now } } });
  await prisma.oidcLogin.create({
    data: { id: sha256Hex(loginCookie), state, nonce, verifier, returnTo: safeReturnTo(returnTo), expiresAt: new Date(now.getTime() + LOGIN_TTL_MS) },
  });
  const url = client.buildAuthorizationUrl(config, {
    redirect_uri: e.OIDC_REDIRECT_URI!,
    scope: e.OIDC_SCOPES,
    code_challenge: await client.calculatePKCECodeChallenge(verifier),
    code_challenge_method: "S256",
    state,
    nonce,
  });
  return { url, loginCookie };
}

export type LoginOutcome =
  | { ok: true; sessionToken: string; returnTo: string; upn: string }
  | { ok: false; reason: "expired" | "denied" | "failed" };

type OidcAccount = Awaited<ReturnType<typeof prisma.user.findUnique>>;

/**
 * Which local account an IdP identity signs into. A LINKED account (externalId set) is matched ONLY by the
 * directory's immutable subject (oid/sub) — never by UPN, which IdP admins / users can rename. The UPN is
 * used exactly once: to link a not-yet-linked account on its first SSO sign-in.
 */
export async function resolveOidcAccount(sub: string, upn: string): Promise<{ ok: true; user: OidcAccount } | { ok: false; reason: string }> {
  const bySub = await prisma.user.findUnique({ where: { externalId: sub } });
  if (bySub) {
    if (bySub.upn !== upn && (await prisma.user.findUnique({ where: { upn }, select: { id: true } }))) {
      return { ok: false, reason: "directory UPN changed to one used by another PatchGate account" };
    }
    return { ok: true, user: bySub };
  }
  const byUpn = await prisma.user.findUnique({ where: { upn } });
  if (byUpn?.externalId) return { ok: false, reason: "UPN belongs to a different (already linked) directory account" };
  return { ok: true, user: byUpn };
}

/** Finish a login from the IdP callback. Never trusts anything that the server did not issue itself. */
export async function finishLogin(callbackUrl: URL, loginCookie: string | undefined, meta: ClientMeta, now = new Date()): Promise<LoginOutcome> {
  const e = env();
  if (!loginCookie) return { ok: false, reason: "expired" };
  // Single use: the record is deleted before the code is redeemed (replays find nothing).
  const rec = await prisma.oidcLogin.delete({ where: { id: sha256Hex(loginCookie) } }).catch(() => null);
  if (!rec || rec.expiresAt < now) return { ok: false, reason: "expired" };

  // Build the callback URL from the configured redirect URI (the request may arrive via an internal
  // hostname behind the reverse proxy), keeping only the IdP's query parameters.
  const current = new URL(e.OIDC_REDIRECT_URI!);
  current.search = callbackUrl.search;

  let claims: Record<string, unknown>;
  let idToken: string | undefined;
  try {
    const tokens = await client.authorizationCodeGrant(await oidcConfig(), current, {
      pkceCodeVerifier: rec.verifier,
      expectedState: rec.state,
      expectedNonce: rec.nonce,
      idTokenExpected: true,
    });
    claims = (tokens.claims() ?? {}) as Record<string, unknown>;
    idToken = tokens.id_token;
  } catch (err: unknown) {
    console.warn("[patchgate] oidc callback failed:", describeError(err));
    await auditAuth({ actor: "system:sso", action: "auth.failed", entity: "User", entityId: "-", payload: { reason: "token exchange or validation failed" }, tenantId: null });
    return { ok: false, reason: "failed" };
  }

  const sub = stringClaim(claims, "oid", "sub");
  const upn = stringClaim(claims, e.OIDC_UPN_CLAIM, "upn", "preferred_username", "email")?.toLowerCase() ?? null;
  const name = stringClaim(claims, "name") ?? upn;
  const role = roleFromClaims(claims, e.OIDC_ROLE_CLAIM, parseRoleMap(e.OIDC_ROLE_MAP!));
  const deny = async (reason: string): Promise<LoginOutcome> => {
    await auditAuth({ actor: upn ?? "unknown", action: "auth.denied", entity: "User", entityId: sub ?? "-", payload: { reason, ip: meta.ip }, tenantId: null });
    return { ok: false, reason: "denied" };
  };
  if (!sub || !upn || !name) return deny("identity claims missing");
  if (!role) return deny("no PatchGate role assigned in the directory");

  const resolved = await resolveOidcAccount(sub, upn);
  if (!resolved.ok) return deny(resolved.reason);
  const existing = resolved.user;
  if (existing && !existing.active) return deny("account deactivated in PatchGate");
  // An IdP only ever signs users into ONE scope (our team, or one bank). It can never create platform staff
  // by default, and an account that lives in another scope (e.g. a platform admin) cannot be reached through it.
  const scopeTenantId = e.OIDC_USER_SCOPE === "platform" ? null : (e.OIDC_USER_SCOPE ?? undefined);
  if (scopeTenantId === undefined) return deny("OIDC_USER_SCOPE not configured");
  if (existing && existing.tenantId !== scopeTenantId) return deny("account belongs to another scope than this identity provider");
  if (scopeTenantId) {
    const bank = await prisma.tenant.findUnique({ where: { id: scopeTenantId }, select: { active: true } });
    if (!bank?.active) return deny("bank for this identity provider is missing or inactive");
  }

  const sessionToken = await authTx(async (tx) => {
    const user = existing
      ? await tx.user.update({ where: { id: existing.id }, data: { upn, name, role, externalId: sub, lastLoginAt: now } })
      : await tx.user.create({ data: { upn, name, role, tenantId: scopeTenantId, externalId: sub, lastLoginAt: now } });
    const token = await createSession(tx, { userId: user.id, now, meta, idToken: idToken ?? null });
    if (existing && existing.role !== role) {
      await auditAuth({ actor: "system:sso", action: "user.role_sync", entity: "User", entityId: user.id, payload: { upn, from: existing.role, to: role }, tenantId: user.tenantId }, tx);
    }
    await auditAuth({ actor: upn, action: "auth.login", entity: "User", entityId: user.id, payload: { method: "oidc", role, ip: meta.ip }, tenantId: user.tenantId }, tx);
    return token;
  });
  return { ok: true, sessionToken, returnTo: rec.returnTo, upn };
}

/** End the session locally; returns the IdP end-session URL (single sign-out) when the IdP supports it. */
export async function logout(sessionToken: string | undefined): Promise<string | null> {
  const e = env();
  const ended = await endSession(sessionToken);
  if (!ended) return null;
  try {
    const config = await oidcConfig();
    if (!config.serverMetadata().end_session_endpoint) return null;
    const params: Record<string, string> = {};
    if (ended.idToken) params.id_token_hint = ended.idToken;
    if (e.OIDC_POST_LOGOUT_REDIRECT_URI) params.post_logout_redirect_uri = e.OIDC_POST_LOGOUT_REDIRECT_URI;
    return client.buildEndSessionUrl(config, params).toString();
  } catch {
    return null;
  }
}

/** Worker step: drop expired / idle sessions and abandoned logins; flush the unknown-user failure summary. */
export async function purgeExpiredAuth(now = new Date()): Promise<{ sessions: number; logins: number; challenges: number; inactiveDisabled: number }> {
  const idleCutoff = new Date(now.getTime() - env().SESSION_IDLE_MINUTES * 60_000);
  const sessions = await prisma.session.deleteMany({ where: { OR: [{ expiresAt: { lt: now } }, { lastSeenAt: { lt: idleCutoff } }] } });
  const logins = await prisma.oidcLogin.deleteMany({ where: { expiresAt: { lt: now } } });
  const challenges = await prisma.authChallenge.deleteMany({ where: { expiresAt: { lt: now } } });
  await flushUnknownLoginSummary(now.getTime());
  // Account policy: deactivate users inactive for longer than SecurityPolicy.inactivityDisableDays.
  const inactive = await disableInactiveUsers(now);
  return { sessions: sessions.count, logins: logins.count, challenges: challenges.count, inactiveDisabled: inactive.disabled };
}
