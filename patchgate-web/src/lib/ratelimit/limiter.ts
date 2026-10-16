import { isIP } from "node:net";

/**
 * In-process token-bucket rate limiter (used by src/proxy.ts).
 * Per-instance memory: behind a load balancer with N instances the effective limit is N×.
 * For multi-instance deployments swap the store for Redis/Postgres — the policy stays the same.
 */

export interface Rule {
  capacity: number; // burst
  perMinute: number; // sustained rate
}

export interface TakeResult {
  ok: boolean;
  remaining: number;
  retryAfterSec: number;
}

interface Bucket {
  tokens: number;
  updated: number;
}

export function createLimiter(opts: { now?: () => number; maxKeys?: number } = {}) {
  const now = opts.now ?? Date.now;
  const maxKeys = opts.maxKeys ?? 20_000;
  const buckets = new Map<string, Bucket>(); // insertion order ≈ LRU (re-inserted on use)

  function evict(): void {
    while (buckets.size > maxKeys) {
      const oldest = buckets.keys().next().value;
      if (oldest === undefined) break;
      buckets.delete(oldest);
    }
  }

  return {
    take(key: string, rule: Rule): TakeResult {
      const t = now();
      const ratePerMs = rule.perMinute / 60_000;
      const prev = buckets.get(key);
      const tokens = prev ? Math.min(rule.capacity, prev.tokens + (t - prev.updated) * ratePerMs) : rule.capacity;
      buckets.delete(key);
      if (tokens >= 1) {
        buckets.set(key, { tokens: tokens - 1, updated: t });
        evict();
        return { ok: true, remaining: Math.floor(tokens - 1), retryAfterSec: 0 };
      }
      buckets.set(key, { tokens, updated: t });
      evict();
      return { ok: false, remaining: 0, retryAfterSec: Math.ceil((1 - tokens) / ratePerMs / 1000) };
    },
    size: () => buckets.size,
  };
}

/** One independent limiter per class, so flooding one class can never evict another's buckets. */
export function createClassLimiters(opts: { now?: () => number; maxKeysPerClass?: number } = {}) {
  const limiters = new Map<string, ReturnType<typeof createLimiter>>();
  return {
    take(cls: string, key: string, rule: Rule): TakeResult {
      let l = limiters.get(cls);
      if (!l) {
        l = createLimiter({ now: opts.now, maxKeys: opts.maxKeysPerClass });
        limiters.set(cls, l);
      }
      return l.take(key, rule);
    },
    size: (cls: string) => limiters.get(cls)?.size() ?? 0,
  };
}

export interface Policy extends Rule {
  name:
    | "auth"
    | "machine"
    | "machine-unauth"
    | "audit"
    | "write"
    | "read"
    | "repo"
    | "page"
    | "connector"
    | "connector-unauth"
    | "connector-enroll"
    | "install";
}

const P = (name: Policy["name"], perMinute: number, capacity = perMinute): Policy => ({ name, perMinute, capacity });

/** Decode once, collapse duplicate slashes, drop trailing slash — so %2D / // / trailing-slash tricks can't change the class. */
export function normalizePath(pathname: string): string {
  let p: string;
  try {
    p = decodeURIComponent(pathname);
  } catch {
    p = pathname;
  }
  p = p.replace(/\/{2,}/g, "/");
  if (p.length > 1 && p.endsWith("/")) p = p.slice(0, -1);
  return p.toLowerCase();
}

const under = (p: string, prefix: string) => p === prefix || p.startsWith(`${prefix}/`);

/** One-line site install endpoints (GET /install/site.sh, /install/bundle/<version>/<file>). */
export const INSTALL_PREFIX = "/install";

/** Connector API prefix (protocol v1). */
export const CONNECTOR_API = "/api/connector/v1";

/**
 * Route classes. Strict where brute force matters, generous where PCs fetch packages.
 * Machine routes (worker/WSUS) are split: a VALID token gets its own generous bucket keyed by the
 * token, so unauthenticated floods can't starve the scheduler or WSUS sync.
 * Connector routes: requests carrying well-formed signed headers (see connectorHeadersWellFormed) get a
 * bucket generous enough for long polling + result bursts, keyed by connector id + address; anything
 * else (junk, missing headers) shares a tiny per-address bucket. Enrolment is tiny too.
 */
export function classifyRequest(method: string, pathname: string, validMachineToken = false, signedConnectorRequest = false): Policy {
  const p = normalizePath(pathname);
  if (under(p, CONNECTOR_API)) {
    if (p === `${CONNECTOR_API}/enroll`) return P("connector-enroll", 10, 5);
    return signedConnectorRequest ? P("connector", 600, 200) : P("connector-unauth", 20, 10);
  }
  // One-line site install (machine traffic, enrolment-code gated): 30 requests per 10 minutes per address.
  if (under(p, INSTALL_PREFIX)) return P("install", 3, 30);
  // /api/account (self-service password change) verifies passwords too: same strict class as sign-in.
  if (p === "/api/dev-login" || under(p, "/api/auth") || under(p, "/api/account")) return P("auth", 20, 10);
  if (under(p, "/api/worker") || under(p, "/api/wsus")) {
    return validMachineToken ? P("machine", 120, 30) : P("machine-unauth", 10, 5);
  }
  if (under(p, "/api/audit")) return P("audit", 20, 10);
  if (under(p, "/api")) return method === "GET" || method === "HEAD" ? P("read", 300, 100) : P("write", 60, 20);
  if (under(p, "/repo")) return P("repo", 1200, 300);
  return P("page", 600, 200);
}

/** Aggregate cap per address across all connectors behind it (one bank NAT may front many sites). */
export const CONNECTOR_PER_ADDRESS: Rule = { perMinute: 3000, capacity: 600 };

const CONNECTOR_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
const NONCE_RE = /^[A-Za-z0-9_-]{16,64}$/;
const SIGNATURE_RE = /^[A-Za-z0-9+/]{86}==$/;
const MAX_SKEW_MS = 5 * 60_000;

/**
 * Cheap, stateless pre-check of the signed-request headers (no DB, no crypto): shape + timestamp
 * freshness. The real verification (key, signature, nonce) happens in the route. Returns the claimed
 * connector id, or null when the request cannot possibly authenticate.
 */
export function connectorHeadersWellFormed(headers: Headers, nowMs: number): string | null {
  const id = headers.get("x-pg-connector") ?? "";
  const ts = headers.get("x-pg-timestamp") ?? "";
  if (!CONNECTOR_ID_RE.test(id) || !/^\d{12,14}$/.test(ts) || Math.abs(nowMs - Number(ts)) > MAX_SKEW_MS) return null;
  if (!NONCE_RE.test(headers.get("x-pg-nonce") ?? "") || !SIGNATURE_RE.test(headers.get("x-pg-signature") ?? "")) return null;
  return id;
}

/** Canonical rate-limit key for an address: strip port/zone, unwrap v4-mapped, collapse IPv6 to its /64. */
export function normalizeIp(raw: string): string | null {
  let a = raw.trim();
  const bracket = /^\[([^\]]+)\](?::\d+)?$/.exec(a); // [v6]:port
  if (bracket) a = bracket[1];
  else if (/^\d{1,3}(\.\d{1,3}){3}:\d+$/.test(a)) a = a.slice(0, a.lastIndexOf(":")); // v4:port
  a = a.replace(/%.*$/, ""); // zone id
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(a);
  if (mapped) a = mapped[1];
  const v = isIP(a);
  if (v === 4) return a;
  if (v !== 6) return null;
  // Expand and keep the first 4 hextets (/64): one subnet = one client.
  const [head, tail = ""] = a.toLowerCase().split("::");
  const h = head ? head.split(":") : [];
  const t = tail ? tail.split(":") : [];
  const full = [...h, ...Array(8 - h.length - t.length).fill("0"), ...t].map((x) => x.padStart(4, "0"));
  return `${full.slice(0, 4).join(":")}::/64`;
}

/**
 * Client address for rate-limit keys. X-Forwarded-For is attacker-controlled unless a trusted
 * reverse proxy appends to it, so it is used ONLY when trustedHops > 0, taking the entry that the
 * outermost trusted proxy added (right-most minus hops-1). Otherwise all traffic shares "direct"
 * (development only — production requires TRUST_PROXY_HOPS ≥ 1, enforced in env.ts).
 */
export function clientIp(headers: Headers, trustedHops: number): string {
  if (trustedHops <= 0) return "direct";
  const chain = (headers.get("x-forwarded-for") ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  const candidate = chain[chain.length - trustedHops];
  return (candidate && normalizeIp(candidate)) ?? "direct";
}

/**
 * Failed-secret counter (like the sign-in lockout, but in memory and per key — e.g. a source address
 * presenting wrong enrolment codes): `maxFailures` failures inside `windowMs` block the key for `blockMs`.
 * Memory is bounded like the limiter (oldest keys evicted).
 */
export function createFailureCounter(opts: { maxFailures: number; windowMs: number; blockMs: number; now?: () => number; maxKeys?: number }) {
  const now = opts.now ?? Date.now;
  const maxKeys = opts.maxKeys ?? 20_000;
  const entries = new Map<string, { count: number; firstAt: number; blockedUntil: number }>();

  function blockedFor(key: string): number {
    const e = entries.get(key);
    if (!e) return 0;
    const left = e.blockedUntil - now();
    return left > 0 ? Math.ceil(left / 1000) : 0;
  }

  return {
    /** Seconds until the key may try again (0 = not blocked). */
    blockedFor,
    /** Count one failure; returns the block (seconds) it caused, 0 when still under the limit. */
    fail(key: string): number {
      const t = now();
      const prev = entries.get(key);
      const fresh = !prev || t - prev.firstAt > opts.windowMs;
      const next = fresh ? { count: 1, firstAt: t, blockedUntil: prev?.blockedUntil ?? 0 } : { ...prev, count: prev.count + 1 };
      const blocked = next.count >= opts.maxFailures ? { count: 0, firstAt: t, blockedUntil: t + opts.blockMs } : next;
      entries.delete(key);
      entries.set(key, blocked);
      while (entries.size > maxKeys) {
        const oldest = entries.keys().next().value;
        if (oldest === undefined) break;
        entries.delete(oldest);
      }
      return blockedFor(key);
    },
    size: () => entries.size,
  };
}
