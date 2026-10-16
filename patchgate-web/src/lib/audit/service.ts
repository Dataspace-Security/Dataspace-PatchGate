import "server-only";
import type { Prisma } from "@prisma/client";
import { prisma } from "@/lib/db";
import { env } from "@/lib/env";
import { RLS_ROLE, withPlatform, withTenant } from "@/lib/tenancy/db";
import { GENESIS_HASH, computeHash, verifyChain } from "./hash-chain";

type Tx = Prisma.TransactionClient;

// Arbitrary constant (first half of a two-int advisory lock). The second half is hashtext(chain), so
// appends are serialised PER CHAIN: banks never wait on each other, and a chain's prevHash never forks.
const AUDIT_LOCK_KEY = 4_242_001;
const PLATFORM_CHAIN = "platform";
const VERIFY_BATCH = 1000;

/** Chain id used in exports / UI: the bank id, or "platform". */
export function chainName(tenantId: string | null): string {
  return tenantId ?? PLATFORM_CHAIN;
}

export interface AuditInput {
  actor: string;
  action: string;
  entity: string;
  entityId: string;
  payload?: Prisma.InputJsonValue;
  /**
   * Which chain the event belongs to: the bank it concerns, or null/omitted = the platform chain
   * (trust decisions, catalog fetches, user/bank administration, sign-in of platform staff).
   * Optional for backward compatibility: existing callers keep writing to the platform chain.
   */
  tenantId?: string | null;
}

/**
 * Make sure the transaction may write this chain under Row-Level Security (the runtime DB role is not
 * the owner, so RLS always applies in production):
 *  - already platform-scoped (withPlatform) → fine for every chain;
 *  - scoped to bank X (withTenant) → only bank X's chain; anything else is a programming error;
 *  - unscoped (a plain prisma.$transaction from fetch / auth / admin code) → scope the REST of that
 *    transaction to this chain (platform, or that bank), so callers cannot get it wrong.
 */
async function ensureChainScope(db: Tx, tenantId: string | null): Promise<void> {
  const [cur] = await db.$queryRaw<{ scope: string | null; tid: string | null }[]>`
    SELECT current_setting('app.scope', true) AS scope, current_setting('app.tenant_id', true) AS tid`;
  if (cur?.scope === "platform") return;
  if (cur?.scope === "tenant") {
    if (cur.tid === tenantId) return;
    throw new Error(`audit: a transaction scoped to one bank cannot write the ${chainName(tenantId)} chain`);
  }
  const scope = tenantId ? "tenant" : "platform";
  await db.$executeRaw`SELECT set_config('app.scope', ${scope}, true), set_config('app.tenant_id', ${tenantId ?? ""}, true), set_config('role', ${RLS_ROLE}, true)`;
}

/**
 * Append an audit event to its chain (bank or platform).
 * Pass `tx` to make it atomic with the business change; an unscoped transaction is scoped to the chain
 * first (see ensureChainScope). Inside withTenant(A) only bank A's chain can be written.
 * Without `tx` the append runs in its own RLS-scoped transaction for that chain.
 */
export async function appendAudit(input: AuditInput, tx?: Tx): Promise<void> {
  const key = env().AUDIT_HMAC_KEY;
  const tenantId = input.tenantId ?? null;
  const run = async (db: Tx) => {
    await ensureChainScope(db, tenantId);
    await db.$executeRaw`SELECT pg_advisory_xact_lock(${AUDIT_LOCK_KEY}::int4, hashtext(${chainName(tenantId)}))`;
    const last = await db.auditEvent.findFirst({ where: { tenantId }, orderBy: { seq: "desc" }, select: { hash: true } });
    const ts = new Date();
    const payload = input.payload ?? {};
    const prevHash = last?.hash ?? GENESIS_HASH;
    const fields = { actor: input.actor, action: input.action, entity: input.entity, entityId: input.entityId };
    const hash = computeHash({ ...fields, tenantId, payload, ts: ts.toISOString(), prevHash }, key);
    await db.auditEvent.create({ data: { ...fields, tenantId, payload, ts, prevHash, hash } });
  };
  if (tx) await run(tx);
  else if (tenantId) await withTenant(tenantId, run);
  else await withPlatform(run);
}

export interface AuditVerification {
  /** Chain checked: bank id, or null = platform chain */
  tenantId: string | null;
  valid: boolean;
  count: number;
  head: string | null;
  /** Human-readable reason when invalid */
  problem: string | null;
  anchorsChecked: number;
}

/**
 * Stream-verify ONE chain (bounded memory) AND cross-check every SIEM anchor exported for it:
 * an anchor whose seq is missing or whose hash differs means rows were deleted or rewritten
 * after export (including tail truncation, which the chain alone cannot detect).
 */
export async function verifyAuditLog(tenantId: string | null = null): Promise<AuditVerification> {
  const key = env().AUDIT_HMAC_KEY;
  // Platform scope: RLS applies to the runtime DB role, and verification walks one chain explicitly.
  const anchors = await withPlatform((tx) =>
    tx.auditAnchor.findMany({
      where: { tenantId, eventCount: { gt: 0 } },
      select: { seq: true, hash: true },
    }),
  );
  const pending = new Map(anchors.map((a) => [a.seq.toString(), a.hash]));
  const anchorsChecked = pending.size;
  const base = { tenantId, anchorsChecked };

  let prev = GENESIS_HASH;
  let count = 0;
  let cursor: bigint | undefined;

  for (;;) {
    const after = cursor;
    const rows = await withPlatform((tx) =>
      tx.auditEvent.findMany({
        where: { tenantId },
        orderBy: { seq: "asc" },
        take: VERIFY_BATCH,
        ...(after !== undefined ? { cursor: { seq: after }, skip: 1 } : {}),
      }),
    );
    if (rows.length === 0) break;

    const verdict = verifyChain(
      rows.map((r) => ({ ...r, ts: r.ts.toISOString() })),
      key,
      prev,
      count,
    );
    if (!verdict.valid) {
      const bad = rows[verdict.brokenAt - count];
      return { ...base, valid: false, count: verdict.brokenAt, head: null, problem: `chain broken at seq ${bad.seq}` };
    }

    for (const r of rows) {
      const expected = pending.get(r.seq.toString());
      if (expected === undefined) continue;
      if (expected !== r.hash) {
        return { ...base, valid: false, count, head: null, problem: `seq ${r.seq} differs from SIEM anchor` };
      }
      pending.delete(r.seq.toString());
    }

    prev = verdict.head;
    count += rows.length;
    cursor = rows[rows.length - 1].seq;
  }

  if (pending.size > 0) {
    const missing = [...pending.keys()].sort((a, b) => (BigInt(a) < BigInt(b) ? -1 : 1));
    return {
      ...base,
      valid: false,
      count,
      head: null,
      problem: `events up to exported anchor seq ${missing[missing.length - 1]} are missing (truncated after export)`,
    };
  }
  return { ...base, valid: true, count, head: count > 0 ? prev : null, problem: null };
}

/** Every chain: the platform chain plus one per bank. */
export async function auditChains(): Promise<(string | null)[]> {
  const tenants = await prisma.tenant.findMany({ orderBy: { createdAt: "asc" }, select: { id: true } });
  return [null, ...tenants.map((t) => t.id)];
}

/**
 * Check an anchor copied from the SIEM (the authoritative, PatchGate-independent copy) against ONE chain.
 * Use when the DB anchors themselves might have been tampered with.
 */
export async function verifySiemAnchor(
  tenantId: string | null,
  seq: bigint,
  hash: string,
): Promise<{ match: boolean; reason: string | null }> {
  const row = await withPlatform((tx) => tx.auditEvent.findFirst({ where: { seq, tenantId }, select: { hash: true } }));
  if (!row) return { match: false, reason: `seq ${seq} not found in this audit chain (deleted?)` };
  if (row.hash !== hash) return { match: false, reason: `seq ${seq} hash differs from SIEM (rewritten?)` };
  return { match: true, reason: null };
}

/** Latest hash + seq of one chain. */
export async function getAuditHead(tenantId: string | null = null): Promise<{ seq: string; hash: string } | null> {
  const last = await withPlatform((tx) =>
    tx.auditEvent.findFirst({
      where: { tenantId },
      orderBy: { seq: "desc" },
      select: { seq: true, hash: true },
    }),
  );
  return last ? { seq: last.seq.toString(), hash: last.hash } : null;
}

const VERIFY_CACHE_MS = 60_000;
const verifyCache = new Map<string, { at: number; result: AuditVerification }>();

/**
 * Full-chain verification is O(n); cache it briefly (per chain) so the audit page / API can't be used
 * to hammer the DB. Tamper alerts still surface within a minute.
 */
export async function verifyAuditLogCached(tenantId: string | null = null): Promise<AuditVerification & { cachedAt: Date }> {
  const now = Date.now();
  const k = chainName(tenantId);
  let hit = verifyCache.get(k);
  if (!hit || now - hit.at > VERIFY_CACHE_MS) {
    hit = { at: now, result: await verifyAuditLog(tenantId) };
    verifyCache.set(k, hit);
  }
  return { ...hit.result, cachedAt: new Date(hit.at) };
}

/** Readiness / monitoring: are ALL chains intact? Returns the first broken one, if any. */
export async function verifyAllChainsCached(): Promise<{ valid: boolean; broken: AuditVerification | null }> {
  for (const chain of await auditChains()) {
    const v = await verifyAuditLogCached(chain);
    if (!v.valid) return { valid: false, broken: v };
  }
  return { valid: true, broken: null };
}
