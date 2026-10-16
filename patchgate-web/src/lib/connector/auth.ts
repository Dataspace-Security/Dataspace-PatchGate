import "server-only";
import { withPlatform } from "@/lib/tenancy";
import { log } from "@/lib/log";
import { appendAudit } from "@/lib/audit/service";
import { PENDING_KEY_TTL_MS, keyFingerprint } from "./enroll";
import { ConnectorAuthError } from "./errors";
import { CONNECTOR_ID_RE } from "./policy";
import { HEADERS, MAX_CLOCK_SKEW_MS, NONCE_RE, timestampFresh, verifyRequest } from "./protocol";

/**
 * Authentication of signed connector requests (protocol.ts §1). Every call except enrol:
 *   x-pg-connector / x-pg-timestamp / x-pg-nonce / x-pg-signature over
 *   "PGC1\n" METHOD "\n" path+query (exactly as sent) "\n" ts "\n" nonce "\n" sha256(body).
 * Rejected: malformed headers, unknown connector, |skew| > 5 min, bad signature (401);
 * revoked connector or suspended bank (403); a nonce seen before (401, replay).
 * The nonce is stored only AFTER the signature checked out, so unauthenticated junk cannot fill the table.
 */

export interface AuthedConnector {
  id: string;
  tenantId: string;
  name: string;
  maxConcurrentInstalls: number;
  bandwidthLimitMbps: number | null;
}

const SIGNATURE_RE = /^[A-Za-z0-9+/]{86}==$/; // base64 of a 64-byte Ed25519 signature
/** Remember a nonce until its timestamp can no longer pass the freshness check (+ margin). */
const NONCE_TTL_MS = MAX_CLOCK_SKEW_MS + 60_000;
/** Don't rewrite lastSeenAt on every single call. */
const TOUCH_EVERY_MS = 30_000;

export interface SignedRequestParts {
  method: string;
  /** path + query exactly as the client sent it */
  pathWithQuery: string;
  headers: Headers;
  body: Uint8Array;
}

/** The request target as sent: pathname + search of req.url (no normalisation). */
export function pathWithQueryOf(req: Request): string {
  const u = new URL(req.url);
  return `${u.pathname}${u.search}`;
}

interface HeaderValues {
  connectorId: string;
  timestamp: string;
  nonce: string;
  signature: string;
}

function readHeaders(h: Headers): HeaderValues {
  const connectorId = h.get(HEADERS.connector) ?? "";
  const timestamp = h.get(HEADERS.timestamp) ?? "";
  const nonce = h.get(HEADERS.nonce) ?? "";
  const signature = h.get(HEADERS.signature) ?? "";
  if (!CONNECTOR_ID_RE.test(connectorId)) throw new ConnectorAuthError("missing or malformed connector id");
  if (!NONCE_RE.test(nonce)) throw new ConnectorAuthError("missing or malformed nonce");
  if (!SIGNATURE_RE.test(signature)) throw new ConnectorAuthError("missing or malformed signature");
  return { connectorId, timestamp, nonce, signature };
}

export async function authenticateConnector(req: SignedRequestParts, now = new Date()): Promise<AuthedConnector> {
  const h = readHeaders(req.headers);
  if (!timestampFresh(h.timestamp, now.getTime())) throw new ConnectorAuthError("timestamp outside the allowed clock skew");

  // Platform scope: the connector's bank is only known after the lookup. Nothing else is read here.
  return withPlatform(async (tx) => {
    const c = await tx.connector.findUnique({
      where: { id: h.connectorId },
      select: {
        id: true,
        tenantId: true,
        name: true,
        publicKey: true,
        pendingPublicKey: true,
        pendingKeyAt: true,
        status: true,
        lastSeenAt: true,
        maxConcurrentInstalls: true,
        bandwidthLimitMbps: true,
        tenant: { select: { active: true } },
      },
    });
    if (!c) throw new ConnectorAuthError("unknown connector");
    let status = c.status;
    if (!verifyRequest(c.publicKey, h.signature, req.method, req.pathWithQuery, h.timestamp, h.nonce, req.body)) {
      // Second phase of a re-key: the re-enrolled connector proves possession of its pending key with its
      // first signed request → that key becomes THE key, the old one stops working (audited).
      const pending = c.pendingPublicKey && c.pendingKeyAt && now.getTime() - c.pendingKeyAt.getTime() <= PENDING_KEY_TTL_MS ? c.pendingPublicKey : null;
      if (!pending || !verifyRequest(pending, h.signature, req.method, req.pathWithQuery, h.timestamp, h.nonce, req.body)) {
        throw new ConnectorAuthError("bad signature");
      }
      if (!c.tenant.active) throw new ConnectorAuthError("bank suspended", 403);
      const { count } = await tx.connector.updateMany({
        where: { id: c.id, tenantId: c.tenantId, pendingPublicKey: pending },
        data: { publicKey: pending, pendingPublicKey: null, pendingKeyAt: null, status: "ACTIVE", enrolledAt: now, lastSeenAt: now },
      });
      if (count !== 1) throw new ConnectorAuthError("bad signature");
      await appendAudit(
        {
          tenantId: c.tenantId,
          actor: `connector:${c.id}`,
          action: "connector.rekey_activated",
          entity: "Connector",
          entityId: c.id,
          payload: { keyFingerprint: keyFingerprint(pending), retiredKeyFingerprint: keyFingerprint(c.publicKey), previousStatus: c.status },
        },
        tx,
      );
      log.info("connector.rekey_activated", { connectorId: c.id, tenantId: c.tenantId });
      status = "ACTIVE";
    }
    // Checked after the signature: only the real key holder learns that it was revoked.
    if (status !== "ACTIVE") throw new ConnectorAuthError("connector revoked", 403);
    if (!c.tenant.active) throw new ConnectorAuthError("bank suspended", 403);

    const stored = await tx.$executeRaw`
      INSERT INTO "ConnectorNonce" ("connectorId", "nonce", "expiresAt")
      VALUES (${c.id}, ${h.nonce}, ${new Date(Math.max(now.getTime(), Number(h.timestamp)) + NONCE_TTL_MS)})
      ON CONFLICT DO NOTHING`;
    if (stored !== 1) throw new ConnectorAuthError("replayed nonce");

    if (!c.lastSeenAt || now.getTime() - c.lastSeenAt.getTime() > TOUCH_EVERY_MS) {
      await tx.connector.updateMany({ where: { id: c.id, tenantId: c.tenantId }, data: { lastSeenAt: now } });
    }
    return {
      id: c.id,
      tenantId: c.tenantId,
      name: c.name,
      maxConcurrentInstalls: c.maxConcurrentInstalls,
      bandwidthLimitMbps: c.bandwidthLimitMbps,
    };
  });
}

/**
 * Cheap pre-check before a large body is read: the claimed connector must exist and be ACTIVE.
 * (The signature over the body is still verified afterwards; this only keeps forged ids from making
 * the server buffer megabytes.)
 */
export async function connectorMayUpload(connectorId: string): Promise<boolean> {
  if (!CONNECTOR_ID_RE.test(connectorId)) return false;
  const c = await withPlatform((tx) => tx.connector.findUnique({ where: { id: connectorId }, select: { status: true, pendingPublicKey: true } }));
  // A re-enrolled connector (pending key) may send its first, key-activating request.
  return c?.status === "ACTIVE" || Boolean(c?.pendingPublicKey);
}

/** Housekeeping: drop nonces that can no longer be replayed (fresh-timestamp window passed). */
export async function purgeExpiredNonces(now = new Date()): Promise<number> {
  return withPlatform(async (tx) => {
    const r = await tx.connectorNonce.deleteMany({ where: { expiresAt: { lt: now } } });
    if (r.count > 0) log.debug("connector.nonces.purged", { count: r.count });
    return r.count;
  });
}
