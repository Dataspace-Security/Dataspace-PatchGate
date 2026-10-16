import "server-only";
import { createHash, randomInt, verify } from "node:crypto";
import { z } from "zod";
import { appendAudit } from "@/lib/audit/service";
import { cacheCurrentAgentBuilds } from "@/lib/deploy/connector-cache";
import { withPlatform, withTenant } from "@/lib/tenancy";
import { log } from "@/lib/log";
import { ConnectorApiError } from "./errors";
import { jobSigningPublicKey } from "./keys";
import { ENROLL_CODE_RE, enrollProofMessage, enrollRequestSchema, publicKeyFromRaw, sha256Hex, type EnrollRequest } from "./protocol";

/**
 * One-time enrolment of a bank site's connector (ARCHITECTURE-HOSTED §3 "Connector identity").
 *  - Our platform admin creates a code for (bank, site name): 100 random bits, shown once, stored only as
 *    SHA-256, valid 24 h, single use.
 *  - The connector proves possession of its locally generated Ed25519 key (signature over code + key),
 *    the code is consumed atomically, and the Connector row is created. A site that re-enrols gets its new
 *    key as PENDING; it becomes the connector's key on its first signed request (two-phase re-key, see
 *    auth.ts). Everything is audited on that bank's chain.
 */

export const ENROLL_CODE_TTL_MS = 24 * 60 * 60_000;
/** A pending re-key that was never used is ignored after this (the site keeps its current key). */
export const PENDING_KEY_TTL_MS = 7 * 24 * 60 * 60_000;
// Crockford-style alphabet without I, L, O, U: 32 symbols → 5 bits each, 20 symbols = 100 bits.
const CODE_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

export function generateEnrollCode(): string {
  const chars = Array.from({ length: 20 }, () => CODE_ALPHABET[randomInt(CODE_ALPHABET.length)]);
  const code = [0, 4, 8, 12, 16].map((i) => chars.slice(i, i + 4).join("")).join("-");
  if (!ENROLL_CODE_RE.test(code)) throw new Error("enrolment code generator produced an invalid code");
  return code;
}

export const enrollCodeHash = (code: string): string => sha256Hex(code);

export const siteNameSchema = z
  .string()
  .trim()
  .min(2, "site name must have at least 2 characters")
  .max(80)
  .regex(/^[A-Za-z0-9][A-Za-z0-9 .,()_/-]*$/, "letters, digits, spaces and . , ( ) _ / - only");

/** Short, non-secret key fingerprint for audit records and the UI. */
export function keyFingerprint(publicKeyRaw: string): string {
  return createHash("sha256").update(Buffer.from(publicKeyRaw, "base64")).digest("hex").slice(0, 16);
}

export interface EnrollResult {
  connectorId: string;
  tenantId: string;
  name: string;
  jobSigningPublicKey: string;
}

function proofValid(req: EnrollRequest): boolean {
  try {
    return verify(null, Buffer.from(enrollProofMessage(req.code, req.publicKey)), publicKeyFromRaw(req.publicKey), Buffer.from(req.proof, "base64"));
  } catch {
    return false;
  }
}

const INVALID_CODE = "invalid, used or expired enrolment code";

/** POST /api/connector/v1/enroll (unsigned: the connector has no identity yet). */
export async function redeemEnrollment(body: unknown, now = new Date()): Promise<EnrollResult> {
  const result = await redeemInTx(body, now);
  await prefetchAgentBuilds(result, now);
  return result;
}

/**
 * After enrolment: queue CACHE_PACKAGE for the current VERIFIED Tactical agent builds (both arches) so the
 * site's PCs can take the agent from the site cache. Best effort and idempotent: a failure here (e.g. the
 * signer is briefly unavailable) never undoes the enrolment; the next deployment needing the agent queues it.
 */
async function prefetchAgentBuilds(r: EnrollResult, now: Date): Promise<void> {
  try {
    const queued = await withTenant(r.tenantId, (tx) => cacheCurrentAgentBuilds(tx, { id: r.connectorId, tenantId: r.tenantId }, now));
    if (queued.length > 0) log.info("connector.agent_cache_requested", { connectorId: r.connectorId, tenantId: r.tenantId, packages: queued });
  } catch (err: unknown) {
    log.warn("connector.agent_cache_failed", { connectorId: r.connectorId, tenantId: r.tenantId, error: err instanceof Error ? err.message : String(err) });
  }
}

async function redeemInTx(body: unknown, now: Date): Promise<EnrollResult> {
  const parsed = enrollRequestSchema.safeParse(body);
  if (!parsed.success) throw new ConnectorApiError(400, `invalid enrolment request: ${parsed.error.issues[0]?.message ?? "malformed"}`);
  const req = parsed.data;
  if (!proofValid(req)) throw new ConnectorApiError(403, "proof of key possession failed");

  return withPlatform(async (tx) => {
    const id = enrollCodeHash(req.code);
    const enrollment = await tx.connectorEnrollment.findUnique({ where: { id }, include: { tenant: { select: { active: true } } } });
    if (!enrollment || enrollment.usedAt || enrollment.expiresAt <= now || !enrollment.tenant.active) {
      throw new ConnectorApiError(403, INVALID_CODE);
    }
    // The bank's job-signing key (per bank with the remote signer). Fetched before anything is written and
    // before any row lock is taken: if the signer is unusable the code stays unused.
    const jobKey = await jobSigningPublicKey(enrollment.tenantId);
    // Single use, even under concurrent redemption: only one UPDATE can flip usedAt.
    const { count } = await tx.connectorEnrollment.updateMany({ where: { id, usedAt: null, expiresAt: { gt: now } }, data: { usedAt: now } });
    if (count !== 1) throw new ConnectorApiError(403, INVALID_CODE);

    const { tenantId, name } = enrollment;
    const existing = await tx.connector.findUnique({ where: { tenantId_name: { tenantId, name } }, select: { id: true, status: true, publicKey: true } });
    // Re-enrolment of an existing site is TWO-PHASE: the new key is only PENDING here. It replaces the
    // current key when it signs its first request (auth.ts); until then the old key keeps working, so an
    // init that is refused after this call (e.g. wrong --job-key-fingerprint) never locks the site out.
    const connector = existing
      ? await tx.connector.update({ where: { id: existing.id }, data: { pendingPublicKey: req.publicKey, pendingKeyAt: now } })
      : await tx.connector.create({ data: { tenantId, name, publicKey: req.publicKey, version: req.version, lastSeenAt: now } });

    await appendAudit(
      {
        tenantId,
        actor: `connector:${connector.id}`,
        action: existing ? "connector.rekey_pending" : "connector.enrolled",
        entity: "Connector",
        entityId: connector.id,
        payload: {
          name,
          version: req.version,
          keyFingerprint: keyFingerprint(req.publicKey),
          enrollmentCreatedBy: enrollment.createdBy,
          ...(existing ? { previousStatus: existing.status, currentKeyFingerprint: keyFingerprint(existing.publicKey) } : {}),
        },
      },
      tx,
    );
    log.info("connector.enrolled", { connectorId: connector.id, tenantId, rekeyed: Boolean(existing) });
    return { connectorId: connector.id, tenantId, name, jobSigningPublicKey: jobKey };
  });
}
