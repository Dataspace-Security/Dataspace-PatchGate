import { createHmac } from "node:crypto";

/**
 * Tamper-evident audit log.
 * Each event = HMAC-SHA256(key, canonical(content + prevHash)).
 * - Key lives outside the DB (env/secret store), so a DB-only attacker cannot re-forge the chain.
 * - Verification always starts at GENESIS, so deleting the oldest rows is detected.
 * - Tail truncation needs an external anchor: ship the head hash to SIEM/WORM (see getAuditHead).
 * Note: seq gaps are NOT treated as tampering — Postgres sequences skip on rolled-back transactions.
 *
 * Multi-bank: there is one chain per bank (tenantId) plus the platform chain (tenantId null), each
 * starting at GENESIS. A bank event's hash also covers its tenantId, so an event cannot be moved into
 * another bank's chain. Platform events omit the field, so chains written before multi-tenancy (all
 * platform) still verify unchanged.
 */

export const GENESIS_HASH = "0".repeat(64);

export interface ChainEntry {
  /** Owning bank; null/undefined = platform chain (not part of the hash material then). */
  tenantId?: string | null;
  ts: string; // ISO-8601, millisecond precision
  actor: string;
  action: string;
  entity: string;
  entityId: string;
  payload: unknown;
  prevHash: string;
  hash: string;
}

/** JSON with sorted object keys so hashing is independent of key order. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj)
    .filter((k) => obj[k] !== undefined)
    .sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(",")}}`;
}

export function computeHash(e: Omit<ChainEntry, "hash">, key: string): string {
  const material = canonicalJson({
    // undefined keys are dropped by canonicalJson: platform events hash exactly as before
    tenantId: e.tenantId ?? undefined,
    ts: e.ts,
    actor: e.actor,
    action: e.action,
    entity: e.entity,
    entityId: e.entityId,
    payload: e.payload,
    prevHash: e.prevHash,
  });
  return createHmac("sha256", key).update(material).digest("hex");
}

export type ChainVerdict = { valid: true; head: string } | { valid: false; brokenAt: number };

/**
 * Verify a contiguous slice of the chain. For batched verification pass the previous
 * batch's head as `startPrevHash` and its length offset as `indexOffset`.
 */
export function verifyChain(
  entries: readonly ChainEntry[],
  key: string,
  startPrevHash: string = GENESIS_HASH,
  indexOffset = 0,
): ChainVerdict {
  let prev = startPrevHash;
  for (let i = 0; i < entries.length; i++) {
    const e = entries[i];
    if (e.prevHash !== prev || computeHash(e, key) !== e.hash) {
      return { valid: false, brokenAt: indexOffset + i };
    }
    prev = e.hash;
  }
  return { valid: true, head: prev };
}
