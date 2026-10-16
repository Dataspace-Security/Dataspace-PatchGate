import "server-only";
import { env } from "@/lib/env";
import { log } from "@/lib/log";
import { enqueueNotification } from "@/lib/notify/enqueue";
import { withPlatform, type Tx } from "@/lib/tenancy/db";
import { GENESIS_HASH, verifyChain } from "./hash-chain";
import { auditChains, chainName } from "./service";

/**
 * Incremental audit-chain verification (H7). The worker tick verifies only the events appended since the
 * stored checkpoint of each chain (AuditVerifyCheckpoint) and records the verdict; /api/ready only READS
 * the verdicts (auditChainsHealthy) — it never scans a chain, so probes stay fast with millions of events.
 *
 * Each run per chain:
 *  - the checkpoint event itself must still exist with the same hash (deleting / rewriting the verified
 *    tail is detected immediately);
 *  - new events are verified from the checkpoint hash (bounded per run; the next tick continues);
 *  - SIEM anchors exported since the last run are checked against the stored events (an anchor beyond the
 *    chain head = truncated after export);
 *  - once a day the chain is re-verified from GENESIS (catches rewrites of older, already verified rows).
 * A broken verdict is sticky until a full re-verification finds the chain intact again.
 */

const BATCH = 1_000;
/** Bound the work one tick does per chain; the rest continues on the next tick. */
const MAX_EVENTS_PER_RUN = 100_000;
export const FULL_REVERIFY_MS = 24 * 60 * 60_000;

interface Checkpoint {
  seq: bigint;
  hash: string;
  count: bigint;
  anchorSeq: bigint;
  valid: boolean;
  problem: string | null;
  fullVerifiedAt: Date;
}

export interface ChainRun {
  chain: string;
  valid: boolean;
  verified: number;
  complete: boolean;
  problem: string | null;
}

async function saveCheckpoint(tx: Tx, chain: string, tenantId: string | null, cp: Checkpoint, now: Date): Promise<void> {
  const data = { tenantId, seq: cp.seq, hash: cp.hash, count: cp.count, anchorSeq: cp.anchorSeq, valid: cp.valid, problem: cp.problem, verifiedAt: now, fullVerifiedAt: cp.fullVerifiedAt };
  await tx.auditVerifyCheckpoint.upsert({ where: { chain }, create: { chain, ...data }, update: data });
}

/** Verify one chain from its checkpoint (or from GENESIS when due / unknown) — one short transaction. */
export async function verifyChainIncremental(tenantId: string | null, now = new Date()): Promise<ChainRun> {
  return withPlatform((tx) => verifyChainTx(tx, tenantId, now), { timeoutMs: 120_000 });
}

async function verifyChainTx(tx: Tx, tenantId: string | null, now: Date): Promise<ChainRun> {
  const key = env().AUDIT_HMAC_KEY;
  const chain = chainName(tenantId);
  const stored = await tx.auditVerifyCheckpoint.findUnique({ where: { chain } });
  const full = !stored || now.getTime() - stored.fullVerifiedAt.getTime() > FULL_REVERIFY_MS;
  if (stored && !stored.valid && !full) return { chain, valid: false, verified: 0, complete: true, problem: stored.problem };

  const start: Checkpoint = full
    ? { seq: BigInt(0), hash: GENESIS_HASH, count: BigInt(0), anchorSeq: BigInt(0), valid: true, problem: null, fullVerifiedAt: now }
    : { ...stored!, problem: null };
  const broken = async (problem: string): Promise<ChainRun> => {
    await saveCheckpoint(tx, chain, tenantId, { ...start, valid: false, problem }, now);
    await enqueueNotification(tx, { event: "AUDIT_CHAIN_BROKEN", chain, chainTenantId: tenantId, problem });
    log.error("audit.chain_broken", { chain, problem });
    return { chain, valid: false, verified: 0, complete: true, problem };
  };

  // The verified tail must still be there, unchanged.
  if (start.seq > BigInt(0)) {
    const row = await tx.auditEvent.findFirst({ where: { tenantId, seq: start.seq }, select: { hash: true } });
    if (!row) return broken(`verified event seq ${start.seq} is missing (deleted or truncated)`);
    if (row.hash !== start.hash) return broken(`verified event seq ${start.seq} was rewritten`);
  }

  let prev = start.hash;
  let lastSeq = start.seq;
  let count = start.count;
  let verified = 0;
  let complete = false;
  const seen = new Map<string, string>(); // seq → hash of events verified in this run (anchor checks)
  while (verified < MAX_EVENTS_PER_RUN) {
    const after = lastSeq;
    const rows = await tx.auditEvent.findMany({ where: { tenantId, seq: { gt: after } }, orderBy: { seq: "asc" }, take: BATCH });
    if (rows.length === 0) {
      complete = true;
      break;
    }
    const verdict = verifyChain(
      rows.map((r) => ({ ...r, ts: r.ts.toISOString() })),
      key,
      prev,
      0,
    );
    if (!verdict.valid) return broken(`chain broken at seq ${rows[verdict.brokenAt].seq}`);
    for (const r of rows) seen.set(r.seq.toString(), r.hash);
    prev = verdict.head;
    lastSeq = rows[rows.length - 1].seq;
    count += BigInt(rows.length);
    verified += rows.length;
    if (rows.length < BATCH) {
      complete = true;
      break;
    }
  }

  // SIEM anchors exported since the last check.
  const anchors = await tx.auditAnchor.findMany({ where: { tenantId, eventCount: { gt: 0 }, seq: { gt: start.anchorSeq } }, orderBy: { seq: "asc" }, select: { seq: true, hash: true } });
  let anchorSeq = start.anchorSeq;
  for (const a of anchors) {
    if (a.seq > lastSeq) {
      if (complete) return broken(`events up to exported anchor seq ${a.seq} are missing (truncated after export)`);
      break; // not verified that far yet: next run
    }
    const hash = seen.get(a.seq.toString()) ?? (await tx.auditEvent.findFirst({ where: { tenantId, seq: a.seq }, select: { hash: true } }))?.hash;
    if (hash === undefined) return broken(`exported anchor seq ${a.seq} is missing from the chain`);
    if (hash !== a.hash) return broken(`seq ${a.seq} differs from SIEM anchor`);
    anchorSeq = a.seq;
  }

  await saveCheckpoint(tx, chain, tenantId, { seq: lastSeq, hash: prev, count, anchorSeq, valid: true, problem: null, fullVerifiedAt: start.fullVerifiedAt }, now);
  return { chain, valid: true, verified, complete, problem: null };
}

/**
 * Chains with nothing new since their checkpoint (same head, no newer anchor, no full run due, verdict
 * valid) — one cheap transaction for all chains so an idle platform costs almost nothing per tick.
 */
async function unchangedChains(chains: readonly (string | null)[], now: Date): Promise<Set<string>> {
  return withPlatform(async (tx) => {
    const cps = new Map((await tx.auditVerifyCheckpoint.findMany()).map((c) => [c.chain, c]));
    const same = new Set<string>();
    for (const tenantId of chains) {
      const cp = cps.get(chainName(tenantId));
      if (!cp || !cp.valid || now.getTime() - cp.fullVerifiedAt.getTime() > FULL_REVERIFY_MS) continue;
      const head = await tx.auditEvent.findFirst({ where: { tenantId }, orderBy: { seq: "desc" }, select: { seq: true, hash: true } });
      const anchor = await tx.auditAnchor.findFirst({ where: { tenantId, eventCount: { gt: 0 } }, orderBy: { seq: "desc" }, select: { seq: true } });
      const headSame = head ? head.seq === cp.seq && head.hash === cp.hash : cp.seq === BigInt(0);
      if (headSame && (anchor?.seq ?? BigInt(0)) <= cp.anchorSeq) same.add(chainName(tenantId));
    }
    return same;
  });
}

/** Worker step: verify every chain incrementally. */
export async function verifyAuditChainsIncremental(now = new Date()): Promise<{ valid: boolean; chains: number; verified: number; brokenChains: number }> {
  let verified = 0;
  let brokenChains = 0;
  const chains = await auditChains();
  const skip = await unchangedChains(chains, now);
  for (const tenantId of chains) {
    if (skip.has(chainName(tenantId))) continue;
    try {
      const r = await verifyChainIncremental(tenantId, now);
      verified += r.verified;
      if (!r.valid) brokenChains++;
    } catch (err: unknown) {
      log.error("audit.verify_failed", { chain: chainName(tenantId), err });
    }
  }
  invalidateHealthCache();
  return { valid: brokenChains === 0, chains: chains.length, verified, brokenChains };
}

// ---------------------------------------------------------------------------------------------
// Readiness: read the stored verdicts only (cached briefly, concurrent probes share one query)
// ---------------------------------------------------------------------------------------------

const HEALTH_CACHE_MS = 15_000;
let healthCache: { at: number; value: boolean | null } | null = null;
let inFlight: Promise<boolean | null> | null = null;

function invalidateHealthCache(): void {
  healthCache = null;
}

/** true = every verified chain intact; false = a chain is broken; null = nothing verified yet. */
export async function auditChainsHealthy(): Promise<boolean | null> {
  if (healthCache && Date.now() - healthCache.at < HEALTH_CACHE_MS) return healthCache.value;
  if (inFlight) return inFlight;
  inFlight = (async () => {
    try {
      const rows = await withPlatform((tx) => tx.auditVerifyCheckpoint.groupBy({ by: ["valid"], _count: { _all: true } }));
      const value = rows.length === 0 ? null : !rows.some((r) => !r.valid && r._count._all > 0);
      healthCache = { at: Date.now(), value };
      return value;
    } finally {
      inFlight = null;
    }
  })();
  return inFlight;
}
