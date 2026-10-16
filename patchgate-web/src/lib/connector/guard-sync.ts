import "server-only";
import { randomBytes } from "node:crypto";
import { log } from "@/lib/log";
import { withTenant, type Tx } from "@/lib/tenancy";
import { MAX_GUARD_ALLOW_ENTRIES, MAX_GUARD_SYNC_PARTS, type GuardAllowEntry } from "./protocol";
import { enqueueJob } from "./queue";
import { OWN_APPROVAL_MEMORY_MS } from "./tactical-activity";

/**
 * TACTICAL_GUARD_SYNC (protocol §8): after a connector start its real-time approval guard resets nothing until
 * it knows which approvals PatchGate authorised. The heartbeat reports guard.allowSetKnown = false → PatchGate
 * signs the baseline here: one entry per PC from its DEPLOY_WINDOWS jobs (union of guids, latest window end;
 * ended windows within OWN_APPROVAL_MEMORY_MS too, so their leftovers are withdrawn quietly, not alerted) plus
 * its audit cursor, in ≤ MAX_GUARD_SYNC_PARTS signed jobs sharing one syncId. At most one sync is outstanding.
 */

const GUARD_SYNC_TTL_MS = 15 * 60_000;
/** Do not sign another sync this soon after the previous one (heartbeats arrive every ~60 s). */
const GUARD_SYNC_MIN_GAP_MS = 2 * 60_000;
const MAX_GUIDS_PER_ENTRY = 2000;

interface DeployRow {
  payload: unknown;
  expiresAt: Date;
}

/** Pure: DEPLOY_WINDOWS jobs → one allow entry per PC (newest windows first when over the protocol cap). */
export function buildAllowEntries(jobs: readonly DeployRow[]): GuardAllowEntry[] {
  const byAgent = new Map<string, { guids: Set<string>; until: number }>();
  for (const j of jobs) {
    const p = j.payload as { agentId?: unknown; guids?: unknown } | null;
    if (typeof p?.agentId !== "string" || !Array.isArray(p.guids)) continue;
    const e = byAgent.get(p.agentId) ?? { guids: new Set<string>(), until: 0 };
    for (const g of p.guids) if (typeof g === "string" && e.guids.size < MAX_GUIDS_PER_ENTRY) e.guids.add(g.toLowerCase());
    e.until = Math.max(e.until, j.expiresAt.getTime());
    byAgent.set(p.agentId, e);
  }
  return [...byAgent.entries()]
    .filter(([, e]) => e.guids.size > 0)
    .sort((a, b) => b[1].until - a[1].until)
    .slice(0, MAX_GUARD_SYNC_PARTS * MAX_GUARD_ALLOW_ENTRIES)
    .map(([agentId, e]) => ({ agentId, guids: [...e.guids], until: new Date(e.until).toISOString() }));
}

/** Queue the signed allow-set baseline for one connector unless one is outstanding. Returns the parts queued. */
export async function ensureGuardSync(tx: Tx, c: { id: string; tenantId: string }, now: Date): Promise<number> {
  await tx.$executeRaw`SELECT pg_advisory_xact_lock(4242007, hashtext(${`guard-sync:${c.id}`}))`;
  const recent = await tx.connectorJob.count({
    where: {
      tenantId: c.tenantId,
      connectorId: c.id,
      type: "TACTICAL_GUARD_SYNC",
      OR: [{ status: { in: ["QUEUED", "DELIVERED"] }, expiresAt: { gt: now } }, { createdAt: { gt: new Date(now.getTime() - GUARD_SYNC_MIN_GAP_MS) } }],
    },
  });
  if (recent > 0) return 0;
  const conn = await tx.connector.findFirst({ where: { id: c.id, tenantId: c.tenantId }, select: { tacticalAuditCursor: true } });
  if (!conn) return 0;
  const jobs = await tx.connectorJob.findMany({
    where: { tenantId: c.tenantId, connectorId: c.id, type: "DEPLOY_WINDOWS", status: { not: "CANCELLED" }, expiresAt: { gt: new Date(now.getTime() - OWN_APPROVAL_MEMORY_MS) } },
    select: { payload: true, expiresAt: true },
  });
  const entries = buildAllowEntries(jobs);
  const parts = Math.max(1, Math.ceil(entries.length / MAX_GUARD_ALLOW_ENTRIES));
  const syncId = `gs_${randomBytes(12).toString("base64url")}`;
  for (let i = 0; i < parts; i++) {
    await enqueueJob(
      tx,
      {
        tenantId: c.tenantId,
        connectorId: c.id,
        type: "TACTICAL_GUARD_SYNC",
        payload: { syncId, part: i + 1, parts, allow: entries.slice(i * MAX_GUARD_ALLOW_ENTRIES, (i + 1) * MAX_GUARD_ALLOW_ENTRIES), auditCursor: conn.tacticalAuditCursor },
        expiresAt: new Date(now.getTime() + GUARD_SYNC_TTL_MS),
      },
      now,
    );
  }
  log.info("connector.guard_sync.queued", { tenantId: c.tenantId, connectorId: c.id, parts, agents: entries.length });
  return parts;
}

/** Heartbeat follow-up (own transaction: a signer hiccup never fails the heartbeat). */
export async function requestGuardSyncIfNeeded(
  c: { id: string; tenantId: string },
  guard: { enabled: boolean; allowSetKnown: boolean } | undefined,
  now = new Date(),
): Promise<number> {
  if (!guard?.enabled || guard.allowSetKnown) return 0;
  try {
    return await withTenant(c.tenantId, (tx) => ensureGuardSync(tx, c, now));
  } catch (err: unknown) {
    log.warn("connector.guard_sync.failed", { tenantId: c.tenantId, connectorId: c.id, err });
    return 0;
  }
}
