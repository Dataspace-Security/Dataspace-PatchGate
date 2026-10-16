import "server-only";
import { appendAudit } from "@/lib/audit/service";
import { log } from "@/lib/log";
import { createFailureCounter, createLimiter, type Rule } from "@/lib/ratelimit/limiter";
import { withPlatform } from "@/lib/tenancy";
import { enrollCodeHash } from "./enroll";
import { ENROLL_CODE_RE } from "./protocol";

/**
 * Enrolment-code gate for the site-bundle download (installers/site/web-install.md):
 *   Authorization: PatchGate-Enrolment <code>
 * The code must belong to an unused, unexpired ConnectorEnrollment of an ACTIVE bank. It is NOT consumed
 * (the connector's enrolment consumes it later). Every failure gets the same 403 (no oracle). Limits:
 * per code hash (30 requests / 10 min) and per source address for failures (10 wrong codes / 10 min block
 * the address for 15 min, like sign-in lockout); the proxy adds the per-address "install" class.
 * The counters are per web process (N replicas = N× the budget). Accepted: codes carry ~100 bits, are single
 * use and expire in 24 h, so these limits only curb noise — the nginx limit is the shared one.
 */

export const AUTH_SCHEME = "PatchGate-Enrolment";
export const FORBIDDEN_BODY = "Forbidden: invalid, used or expired enrolment code\n";

const PER_CODE: Rule = { capacity: 30, perMinute: 3 };
const codeLimiter = createLimiter();
const failures = createFailureCounter({ maxFailures: 10, windowMs: 10 * 60_000, blockMs: 15 * 60_000 });

/** Pure: the code from the Authorization header, or null when absent / malformed. */
export function parseEnrolmentAuth(header: string | null): string | null {
  if (!header) return null;
  const m = /^PatchGate-Enrolment[ \t]+(\S+)[ \t]*$/i.exec(header);
  const code = m?.[1] ?? "";
  return ENROLL_CODE_RE.test(code) ? code : null;
}

export interface BundleGrant {
  tenantId: string;
  siteName: string;
  /** first 16 hex of the code's SHA-256 (= the enrolment's audit entity id); never the code */
  codeHashPrefix: string;
}

export type AccessDecision = { ok: true; grant: BundleGrant } | { ok: false; status: 403 | 429; retryAfterSec?: number };

/** Look the code up (platform scope: ConnectorEnrollment is RLS-protected per bank). Not consumed. */
async function lookup(code: string, now: Date): Promise<BundleGrant | null> {
  const id = enrollCodeHash(code);
  const e = await withPlatform((tx) =>
    tx.connectorEnrollment.findUnique({ where: { id }, select: { tenantId: true, name: true, usedAt: true, expiresAt: true, tenant: { select: { active: true } } } }),
  );
  if (!e || e.usedAt || e.expiresAt <= now || !e.tenant.active) return null;
  return { tenantId: e.tenantId, siteName: e.name, codeHashPrefix: id.slice(0, 16) };
}

export async function authorizeBundleAccess(authorization: string | null, ip: string, now = new Date()): Promise<AccessDecision> {
  const blocked = failures.blockedFor(ip);
  if (blocked > 0) return { ok: false, status: 429, retryAfterSec: blocked };
  const code = parseEnrolmentAuth(authorization);
  const hash = code ? enrollCodeHash(code) : null;
  if (hash) {
    const r = codeLimiter.take(hash, PER_CODE);
    if (!r.ok) return { ok: false, status: 429, retryAfterSec: r.retryAfterSec };
  }
  const grant = code ? await lookup(code, now) : null;
  if (grant) return { ok: true, grant };
  const blockedNow = failures.fail(ip);
  log.warn("install.code_rejected", { ip, codeHashPrefix: hash?.slice(0, 16) ?? null, reason: code ? "unknown, used or expired" : "missing or malformed", blocked: blockedNow > 0 });
  return { ok: false, status: 403 };
}

/** Audit one bundle file download on the BANK's chain (never the code). */
export async function auditBundleDownload(grant: BundleGrant, d: { version: string; file: string; ip: string; range: string | null; size: number }): Promise<void> {
  await appendAudit({
    tenantId: grant.tenantId,
    actor: `install:${grant.codeHashPrefix}`,
    action: "connector.bundle_downloaded",
    entity: "ConnectorEnrollment",
    entityId: grant.codeHashPrefix,
    payload: { siteName: grant.siteName, version: d.version, file: d.file, sourceIp: d.ip, range: d.range, size: d.size, codeHashPrefix: grant.codeHashPrefix },
  });
}
