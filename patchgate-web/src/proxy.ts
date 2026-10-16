import { createHash, timingSafeEqual } from "node:crypto";
import { NextResponse, type NextRequest } from "next/server";
import {
  CONNECTOR_API,
  CONNECTOR_PER_ADDRESS,
  INSTALL_PREFIX,
  classifyRequest,
  clientIp,
  connectorHeadersWellFormed,
  createClassLimiters,
  normalizePath,
} from "@/lib/ratelimit/limiter";
import { idpOriginOf, securityHeaders } from "@/lib/http/security-headers";

/**
 * Rate limiting for every API call, page and repo download (Next.js 16 Proxy, Node.js runtime).
 * - Keys = client address × route class; each class has its own store (no cross-class eviction).
 * - Worker/WSUS calls with a VALID token are keyed by the token, so unauthenticated floods can't
 *   starve the scheduler or WSUS sync; bad/missing tokens share a tiny per-address bucket.
 * - Production requires TRUST_PROXY_HOPS ≥ 1 (bank reverse proxy) — enforced in env.ts — so
 *   X-Forwarded-For gives per-client keys; without a trusted proxy it is ignored (spoofable).
 * - Connector API (/api/connector/v1): requests with well-formed signed headers are keyed by the claimed
 *   connector id + address (generous: long poll + result bursts) AND share an aggregate per-address cap;
 *   junk without them gets a tiny per-address bucket. Signatures are verified in the route.
 * - One-line site install (/install/*): own per-address class; never redirected to /login (machine traffic).
 */

const limiters = createClassLimiters();
const SSO_ON = ["OIDC_ISSUER_URL", "OIDC_CLIENT_ID", "OIDC_REDIRECT_URI", "OIDC_ROLE_MAP"].every((k) => !!process.env[k]);
const SESSION_COOKIE = "__Host-pg_session"; // keep in sync with lib/auth/tokens.ts
const PUBLIC_PAGES = ["/login"];
const IS_DEV = process.env.NODE_ENV === "development";
// Same resolution as authMode() in lib/env.ts (kept dependency-free here): explicit AUTH_MODE, else OIDC
// when configured, else the dev switcher in development, else local login (the production default).
const AUTH_MODE = process.env.AUTH_MODE ?? (SSO_ON ? "oidc" : IS_DEV ? "dev" : "local");
const LOGIN_REQUIRED = AUTH_MODE !== "dev";
const IDP_ORIGIN = idpOriginOf(process.env.OIDC_ISSUER_URL);

function withSecurityHeaders(res: NextResponse, https: boolean): NextResponse {
  for (const [k, v] of Object.entries(securityHeaders({ isDev: IS_DEV, idpOrigin: IDP_ORIGIN, https }))) res.headers.set(k, v);
  return res;
}
const trustedHops = Math.max(0, Math.min(5, Number.parseInt(process.env.TRUST_PROXY_HOPS ?? "0", 10) || 0));

function sha(s: string): Buffer {
  return createHash("sha256").update(s).digest();
}

/** Constant-time check of the machine token header against WORKER_TOKEN / WSUS_TOKEN. */
function validMachineToken(req: NextRequest, path: string): string | null {
  const isWorker = path.startsWith("/api/worker");
  const given = req.headers.get(isWorker ? "x-worker-token" : "x-wsus-token");
  const expected = isWorker ? process.env.WORKER_TOKEN : process.env.WSUS_TOKEN;
  if (!given || !expected) return null;
  const a = sha(given);
  return timingSafeEqual(a, sha(expected)) ? a.toString("hex").slice(0, 16) : null;
}

export function proxy(request: NextRequest) {
  return withSecurityHeaders(handle(request), request.nextUrl.protocol === "https:" || request.headers.get("x-forwarded-proto") === "https");
}

function handle(request: NextRequest): NextResponse {
  const path = normalizePath(request.nextUrl.pathname);
  const isMachine = path.startsWith("/api/worker") || path.startsWith("/api/wsus");
  const tokenId = isMachine ? validMachineToken(request, path) : null;

  const isConnector = path === CONNECTOR_API || path.startsWith(`${CONNECTOR_API}/`);
  const connectorId = isConnector ? connectorHeadersWellFormed(request.headers, Date.now()) : null;

  const policy = classifyRequest(request.method, path, tokenId !== null, connectorId !== null);
  const ip = clientIp(request.headers, trustedHops);
  const key = tokenId ? `token:${tokenId}` : connectorId ? `connector:${connectorId}|${ip}` : ip;
  let r = limiters.take(policy.name, key, policy);
  if (r.ok && connectorId) {
    // Many claimed ids from one address still share one ceiling.
    const agg = limiters.take("connector-address", ip, CONNECTOR_PER_ADDRESS);
    if (!agg.ok) r = agg;
  }

  if (!r.ok) {
    const headers = {
      "Retry-After": String(r.retryAfterSec),
      "RateLimit-Limit": String(policy.perMinute),
      "RateLimit-Remaining": "0",
    };
    if (path.startsWith("/api/")) {
      return NextResponse.json({ success: false, data: null, error: "Too many requests" }, { status: 429, headers });
    }
    return new NextResponse("Too many requests", { status: 429, headers });
  }

  // Pages without a session cookie go straight to sign-in whenever real login is on (local or OIDC;
  // not the development user switcher). The session itself is validated server-side.
  // /install/* is machine traffic (curl on a new site VM, enrolment-code gated in the route): never redirected.
  const isInstall = path === INSTALL_PREFIX || path.startsWith(`${INSTALL_PREFIX}/`);
  const isPage = !path.startsWith("/api/") && !path.startsWith("/repo/") && path !== "/repo" && !isInstall;
  if (LOGIN_REQUIRED && isPage && !PUBLIC_PAGES.includes(path) && !request.cookies.has(SESSION_COOKIE)) {
    const login = new URL("/login", request.url);
    login.searchParams.set("returnTo", `${request.nextUrl.pathname}${request.nextUrl.search}`);
    return NextResponse.redirect(login);
  }

  const res = NextResponse.next();
  res.headers.set("RateLimit-Limit", String(policy.perMinute));
  res.headers.set("RateLimit-Remaining", String(r.remaining));
  return res;
}

export const config = {
  // Everything except Next.js build assets and the favicon.
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
