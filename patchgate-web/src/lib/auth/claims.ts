import type { UserRole } from "@prisma/client";
import type { ActiveRole } from "./roles";

/**
 * Pure SSO helpers: IdP claim → PatchGate role, safe post-login redirects, session lifetime rules.
 * Roles are owned by the bank IdP (AD groups / Entra app roles) and re-read on every login.
 */

// Only the two active roles can come from an IdP (the same for OIDC_USER_SCOPE=platform and a bank);
// the retired VIEWER / OPERATOR / APPROVER are refused at start-up (env.ts validates OIDC_ROLE_MAP).
const ROLE_RANK: Readonly<Record<ActiveRole, number>> = { AUDITOR: 0, ADMIN: 1 };
const ROLES = new Set<string>(Object.keys(ROLE_RANK));

/** "PatchGate.Admin=ADMIN; PatchGate.Auditor=AUDITOR" → Map (IdP value → role). Throws on bad input. */
export function parseRoleMap(spec: string): Map<string, UserRole> {
  const map = new Map<string, UserRole>();
  for (const part of spec.split(/[;\n]/).map((p) => p.trim()).filter(Boolean)) {
    const eq = part.lastIndexOf("=");
    const key = eq > 0 ? part.slice(0, eq).trim() : "";
    const role = eq > 0 ? part.slice(eq + 1).trim().toUpperCase() : "";
    if (!key || !ROLES.has(role)) throw new Error(`Invalid OIDC_ROLE_MAP entry "${part}" (roles: ADMIN, AUDITOR)`);
    map.set(key, role as UserRole);
  }
  if (map.size === 0) throw new Error("OIDC_ROLE_MAP is empty");
  return map;
}

/** Read a claim by dotted path ("realm_access.roles" for Keycloak, "roles" for Entra). */
export function claimAt(claims: Record<string, unknown>, path: string): unknown {
  let cur: unknown = claims;
  for (const seg of path.split(".")) {
    if (cur === null || typeof cur !== "object") return undefined;
    cur = (cur as Record<string, unknown>)[seg];
  }
  return cur;
}

/** Highest mapped role among the user's IdP roles/groups; null = not authorised for PatchGate. */
export function roleFromClaims(claims: Record<string, unknown>, claimPath: string, map: ReadonlyMap<string, UserRole>): UserRole | null {
  const raw = claimAt(claims, claimPath);
  const values = Array.isArray(raw) ? raw : typeof raw === "string" ? [raw] : [];
  let best: UserRole | null = null;
  for (const v of values) {
    if (typeof v !== "string") continue;
    const role = map.get(v);
    if (role && (best === null || rank(role) > rank(best))) best = role;
  }
  return best;
}

function rank(role: UserRole): number {
  return role in ROLE_RANK ? ROLE_RANK[role as ActiveRole] : -1;
}

/** First non-empty string claim among the candidates. */
export function stringClaim(claims: Record<string, unknown>, ...paths: string[]): string | null {
  for (const p of paths) {
    const v = claimAt(claims, p);
    if (typeof v === "string" && v.trim()) return v.trim();
  }
  return null;
}

/** Only same-site relative paths survive (no "//evil", no "/\\evil", no scheme). Default "/". */
export function safeReturnTo(raw: string | null | undefined): string {
  if (!raw || raw.length > 512) return "/";
  if (!raw.startsWith("/") || raw.startsWith("//") || raw.startsWith("/\\")) return "/";
  if (/[\u0000-\u001f\\]/.test(raw)) return "/";
  if (raw.startsWith("/api/") || raw.startsWith("/login")) return "/";
  return raw;
}

export interface SessionTimes {
  lastSeenAt: Date;
  expiresAt: Date;
}

/** Valid = before the absolute cap AND active within the idle window. */
export function sessionIsLive(s: SessionTimes, now: Date, idleMinutes: number): boolean {
  if (now >= s.expiresAt) return false;
  return now.getTime() - s.lastSeenAt.getTime() < idleMinutes * 60_000;
}

/** Throttle "last seen" writes: refresh at most once a minute per session. */
export function shouldTouch(lastSeenAt: Date, now: Date): boolean {
  return now.getTime() - lastSeenAt.getTime() >= 60_000;
}
