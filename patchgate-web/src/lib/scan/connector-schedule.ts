import "server-only";
import { withPlatform, withTenant, type Tx } from "@/lib/tenancy";
import { log } from "@/lib/log";
import { activeConnectors, type ActiveConnector } from "@/lib/connector/routing";
import { enqueueJob } from "@/lib/connector/queue";
import { MAX_AGENTS_PER_JOB, MAX_TACTICAL_AUDIT_EVENTS, type JobPackage } from "@/lib/connector/protocol";
import { env } from "@/lib/env";
import { ensurePackageCached } from "@/lib/deploy/connector-cache";
import { rebuildDiscovered } from "@/lib/discovery/service";
import { wuScanCab } from "@/lib/winupdate/hooks";

/**
 * Inventory schedules for connector-backed banks (the connector replaces direct Tactical reads):
 *   SYNC_AGENTS  every AGENT_SYNC_MINUTES (default 15) per connector — one Tactical API call, no PC traffic
 *   TACTICAL_AUDIT_SYNC every 10 min per connector (Tactical seal: catch-up / backstop of the connector's
 *                real-time guard, which reads the audit log + approvals itself every ~30 s and pushes them)
 *   COLLECT (updates only) — only for connectors WITHOUT the real-time guard (older versions, or guard off):
 *                every 10 min while a human acted in the site's Tactical in the last 2 h (approval drift)
 *   SCAN         daily per PC, batches of ≤ 200 agents
 *   COLLECT      every 6 h per PC (updates + software + agent version), batches of ≤ 200
 *   WU_SCAN      daily per connector when the winupdate pipeline has a verified offline scan catalog
 *                (the cab is cached at the site first with CACHE_PACKAGE)
 * Offline connectors get no new periodic work: what is queued waits, nothing piles up.
 * PCs are marked when their batch is scheduled (lastScanRequestedAt / ingestAttemptAt), so a batch is
 * never scheduled twice while its result is outstanding.
 */

/** SYNC_AGENTS interval (AGENT_SYNC_MINUTES, 5..1440, default 15). */
export function syncIntervalMs(): number {
  return env().AGENT_SYNC_MINUTES * 60_000;
}
export const TACTICAL_AUDIT_INTERVAL_MS = 10 * 60_000;
/** Connectors without the real-time guard: after out-of-band activity, approvals are re-read this long. */
export const HUMAN_ACTIVITY_WINDOW_MS = 2 * 60 * 60_000;
export const RESCAN_INTERVAL_MS = 24 * 60 * 60_000;
export const COLLECT_INTERVAL_MS = 6 * 60 * 60_000;
export const WU_SCAN_INTERVAL_MS = 24 * 60 * 60_000;
/** A PC that failed (offline) is retried after this. */
export const RETRY_UNREACHABLE_MS = 60 * 60_000;
/** Bound the work one tick creates per connector (5 × 200 = 1,000 PCs). */
const MAX_BATCHES_PER_TICK = 5;

const JOB_TTL = {
  SYNC_AGENTS: 60 * 60_000,
  SCAN: 6 * 60 * 60_000,
  COLLECT: 6 * 60 * 60_000,
  WU_SCAN: 12 * 60 * 60_000,
  TACTICAL_AUDIT_SYNC: 30 * 60_000,
} as const;

export interface ScheduleSummary {
  sync: number;
  scan: number;
  collect: number;
  wuScan: number;
  tacticalAudit: number;
  approvalCheck: number;
  skippedOffline: number;
}

/** Jobs of a type whose result is still outstanding (queued, delivered, or returned but not yet applied). */
async function outstanding(tx: Tx, connectorId: string, type: "SYNC_AGENTS" | "TACTICAL_AUDIT_SYNC"): Promise<number> {
  return tx.connectorJob.count({
    where: {
      connectorId,
      type,
      OR: [{ status: { in: ["QUEUED", "DELIVERED"] } }, { status: "SUCCEEDED", processedAt: null }],
    },
  });
}

/**
 * Queue a SYNC_AGENTS job now ("Sync agents now" / "Request scan" on the Endpoints page). De-duplicated: when
 * one is still outstanding nothing is added. Returns whether a job was queued.
 */
export async function requestAgentSync(tx: Tx, c: { id: string; tenantId: string }, now = new Date()): Promise<boolean> {
  if ((await outstanding(tx, c.id, "SYNC_AGENTS")) > 0) return false;
  await enqueueJob(tx, { tenantId: c.tenantId, connectorId: c.id, type: "SYNC_AGENTS", payload: {}, expiresAt: new Date(now.getTime() + JOB_TTL.SYNC_AGENTS) }, now);
  return true;
}

/** Queue the next Tactical audit-log read for a connector (from its stored cursor). */
export async function enqueueTacticalAudit(tx: Tx, c: { id: string; tenantId: string }, afterId: number, now: Date): Promise<void> {
  await enqueueJob(
    tx,
    {
      tenantId: c.tenantId,
      connectorId: c.id,
      type: "TACTICAL_AUDIT_SYNC",
      payload: { afterId: Math.max(0, afterId), limit: MAX_TACTICAL_AUDIT_EVENTS },
      expiresAt: new Date(now.getTime() + JOB_TTL.TACTICAL_AUDIT_SYNC),
    },
    now,
  );
}

async function scheduleTacticalAudit(tx: Tx, c: ActiveConnector, now: Date): Promise<number> {
  if ((await outstanding(tx, c.id, "TACTICAL_AUDIT_SYNC")) > 0) return 0;
  const recent = await tx.connectorJob.count({
    where: { connectorId: c.id, type: "TACTICAL_AUDIT_SYNC", createdAt: { gt: new Date(now.getTime() - TACTICAL_AUDIT_INTERVAL_MS) }, status: { not: "CANCELLED" } },
  });
  if (recent > 0) return 0;
  const row = await tx.connector.findFirst({ where: { id: c.id, tenantId: c.tenantId }, select: { tacticalAuditCursor: true } });
  await enqueueTacticalAudit(tx, c, row?.tacticalAuditCursor ?? 0, now);
  return 1;
}

/** The connector's last heartbeat reports an armed real-time guard (protocol §8): it resets foreign approvals itself. */
export function guardArmed(heartbeat: unknown): boolean {
  const g = (heartbeat as { guard?: { enabled?: unknown; allowSetKnown?: unknown } } | null)?.guard;
  return g?.enabled === true && g.allowSetKnown === true;
}

/**
 * Fallback for connectors WITHOUT an armed real-time guard (older versions, guard off, allow-set not received):
 * while a human was active in the site's Tactical (last HUMAN_ACTIVITY_WINDOW_MS), re-read every PC's update
 * approvals each TACTICAL_AUDIT_INTERVAL_MS: Tactical does not audit approval changes, PatchGate compares them
 * with its own (approval drift → alert + RESET_APPROVALS, tactical-activity.ts). Updates only: Tactical-server
 * reads, no PC traffic. With the guard, approvals are checked every ~30 s on the site and this is not needed.
 */
async function scheduleApprovalCheck(tx: Tx, c: ActiveConnector, now: Date): Promise<number> {
  const row = await tx.connector.findFirst({ where: { id: c.id, tenantId: c.tenantId }, select: { tacticalHumanSeenAt: true, heartbeat: true } });
  if (guardArmed(row?.heartbeat)) return 0;
  if (!row?.tacticalHumanSeenAt || now.getTime() - row.tacticalHumanSeenAt.getTime() > HUMAN_ACTIVITY_WINDOW_MS) return 0;
  const recent = await tx.connectorJob.count({
    where: { connectorId: c.id, type: "COLLECT", createdAt: { gt: new Date(now.getTime() - TACTICAL_AUDIT_INTERVAL_MS) }, payload: { path: ["software"], equals: false } },
  });
  if (recent > 0) return 0;
  const endpoints = await tx.endpoint.findMany({ where: { tenantId: c.tenantId, connectorId: c.id }, orderBy: { id: "asc" }, select: { tacticalAgentId: true } });
  let jobs = 0;
  for (let i = 0; i < endpoints.length; i += MAX_AGENTS_PER_JOB) {
    const agentIds = endpoints.slice(i, i + MAX_AGENTS_PER_JOB).map((e) => e.tacticalAgentId);
    await enqueueJob(
      tx,
      { tenantId: c.tenantId, connectorId: c.id, type: "COLLECT", payload: { agentIds, updates: true, software: false, agent: false }, expiresAt: new Date(now.getTime() + TACTICAL_AUDIT_INTERVAL_MS * 3) },
      now,
    );
    jobs++;
  }
  return jobs;
}

async function scheduleSync(tx: Tx, c: ActiveConnector, now: Date): Promise<number> {
  const recent = await tx.connectorJob.count({
    where: {
      connectorId: c.id,
      type: "SYNC_AGENTS",
      OR: [{ status: { in: ["QUEUED", "DELIVERED"] } }, { createdAt: { gt: new Date(now.getTime() - syncIntervalMs()) }, status: { not: "CANCELLED" } }],
    },
  });
  if (recent > 0) return 0;
  await enqueueJob(tx, { tenantId: c.tenantId, connectorId: c.id, type: "SYNC_AGENTS", payload: {}, expiresAt: new Date(now.getTime() + JOB_TTL.SYNC_AGENTS) }, now);
  return 1;
}

async function scheduleScan(tx: Tx, c: ActiveConnector, now: Date): Promise<number> {
  const cutoff = new Date(now.getTime() - RESCAN_INTERVAL_MS);
  let jobs = 0;
  for (let i = 0; i < MAX_BATCHES_PER_TICK; i++) {
    const due = await tx.endpoint.findMany({
      where: { tenantId: c.tenantId, connectorId: c.id, OR: [{ lastScanRequestedAt: null }, { lastScanRequestedAt: { lt: cutoff } }] },
      orderBy: { lastScanRequestedAt: { sort: "asc", nulls: "first" } },
      take: MAX_AGENTS_PER_JOB,
      select: { id: true, tacticalAgentId: true },
    });
    if (due.length === 0) break;
    await enqueueJob(
      tx,
      { tenantId: c.tenantId, connectorId: c.id, type: "SCAN", payload: { agentIds: due.map((e) => e.tacticalAgentId) }, expiresAt: new Date(now.getTime() + JOB_TTL.SCAN) },
      now,
    );
    await tx.endpoint.updateMany({ where: { id: { in: due.map((e) => e.id) }, tenantId: c.tenantId }, data: { lastScanRequestedAt: now } });
    jobs++;
  }
  return jobs;
}

async function scheduleCollect(tx: Tx, c: ActiveConnector, now: Date): Promise<number> {
  const readCutoff = new Date(now.getTime() - COLLECT_INTERVAL_MS);
  const attemptCutoff = new Date(now.getTime() - RETRY_UNREACHABLE_MS);
  let jobs = 0;
  for (let i = 0; i < MAX_BATCHES_PER_TICK; i++) {
    const due = await tx.endpoint.findMany({
      where: {
        tenantId: c.tenantId,
        connectorId: c.id,
        AND: [
          { OR: [{ lastScanAt: null }, { lastScanAt: { lt: readCutoff } }] },
          { OR: [{ ingestAttemptAt: null }, { ingestAttemptAt: { lt: attemptCutoff } }] },
        ],
      },
      orderBy: { ingestAttemptAt: { sort: "asc", nulls: "first" } },
      take: MAX_AGENTS_PER_JOB,
      select: { id: true, tacticalAgentId: true },
    });
    if (due.length === 0) break;
    await enqueueCollect(tx, c, due, now);
    jobs++;
  }
  return jobs;
}

/** One COLLECT batch (also used to confirm installs); marks the PCs so they are not batched twice. */
export async function enqueueCollect(
  tx: Tx,
  c: { id: string; tenantId: string },
  endpoints: readonly { id: string; tacticalAgentId: string }[],
  now: Date,
  notBefore?: Date,
): Promise<string> {
  const job = await enqueueJob(
    tx,
    {
      tenantId: c.tenantId,
      connectorId: c.id,
      type: "COLLECT",
      payload: { agentIds: endpoints.map((e) => e.tacticalAgentId), updates: true, software: true, agent: true },
      notBefore,
      expiresAt: new Date((notBefore ?? now).getTime() + JOB_TTL.COLLECT),
    },
    now,
  );
  await tx.endpoint.updateMany({ where: { id: { in: endpoints.map((e) => e.id) }, tenantId: c.tenantId }, data: { ingestAttemptAt: now } });
  return job.id;
}

/**
 * A WU_SCAN asked for with "Request scan of all PCs" is due once the requested agent sync has been applied
 * (so PCs Tactical just enrolled are included) and no WU_SCAN is outstanding. Order: SYNC_AGENTS → SCAN → WU_SCAN.
 */
async function wuScanRequested(tx: Tx, c: ActiveConnector): Promise<Date | null> {
  const row = await tx.connector.findFirst({ where: { id: c.id, tenantId: c.tenantId }, select: { wuScanRequestedAt: true } });
  if (!row?.wuScanRequestedAt) return null;
  if ((await outstanding(tx, c.id, "SYNC_AGENTS")) > 0) return null;
  const inFlight = await tx.connectorJob.count({ where: { connectorId: c.id, type: "WU_SCAN", status: { in: ["QUEUED", "DELIVERED"] } } });
  return inFlight > 0 ? null : row.wuScanRequestedAt;
}

async function scheduleWuScan(tx: Tx, c: ActiveConnector, cab: JobPackage, now: Date): Promise<number> {
  const requested = await wuScanRequested(tx, c);
  if (!requested) {
    const recent = await tx.connectorJob.count({
      where: { connectorId: c.id, type: "WU_SCAN", createdAt: { gt: new Date(now.getTime() - WU_SCAN_INTERVAL_MS) }, status: { not: "CANCELLED" } },
    });
    if (recent > 0) return 0;
  }
  // The site must hold the signed scan catalog before any PC can scan against it (the request waits for it).
  const cache = await ensurePackageCached(tx, c, cab, now);
  if (cache.state !== "cached") return 0;
  if (requested) await tx.connector.updateMany({ where: { id: c.id, tenantId: c.tenantId, wuScanRequestedAt: requested }, data: { wuScanRequestedAt: null } });
  const endpoints = await tx.endpoint.findMany({ where: { tenantId: c.tenantId, connectorId: c.id }, orderBy: { id: "asc" }, select: { tacticalAgentId: true } });
  let jobs = 0;
  for (let i = 0; i < endpoints.length; i += MAX_AGENTS_PER_JOB) {
    const agentIds = endpoints.slice(i, i + MAX_AGENTS_PER_JOB).map((e) => e.tacticalAgentId);
    await enqueueJob(tx, { tenantId: c.tenantId, connectorId: c.id, type: "WU_SCAN", payload: { agentIds, scanCab: cab }, expiresAt: new Date(now.getTime() + JOB_TTL.WU_SCAN) }, now);
    jobs++;
  }
  return jobs;
}

/** Worker step: create the periodic inventory jobs for every online connector. */
export async function scheduleConnectorInventory(now = new Date()): Promise<ScheduleSummary> {
  const summary: ScheduleSummary = { sync: 0, scan: 0, collect: 0, wuScan: 0, tacticalAudit: 0, approvalCheck: 0, skippedOffline: 0 };
  for (const c of await activeConnectors(now)) {
    if (!c.online) {
      summary.skippedOffline++;
      continue;
    }
    try {
      await withTenant(
        c.tenantId,
        async (tx) => {
          // One scheduler per connector at a time (several web instances may tick).
          await tx.$executeRaw`SELECT pg_advisory_xact_lock(4242002, hashtext(${`schedule:${c.id}`}))`;
          summary.sync += await scheduleSync(tx, c, now);
          summary.scan += await scheduleScan(tx, c, now);
          summary.collect += await scheduleCollect(tx, c, now);
          summary.tacticalAudit += await scheduleTacticalAudit(tx, c, now);
          summary.approvalCheck += await scheduleApprovalCheck(tx, c, now);
          const cab = await wuScanCab(tx);
          if (cab) summary.wuScan += await scheduleWuScan(tx, c, cab, now);
        },
        { timeoutMs: 60_000 },
      );
    } catch (err: unknown) {
      log.error("connector.schedule.failed", { connectorId: c.id, tenantId: c.tenantId, err });
    }
  }
  return summary;
}

/**
 * Worker step: rebuild a connector-backed bank's discovery list when COLLECT pages with software arrived
 * since the last rebuild (local work only, no internet). Debounced to once per tick per bank.
 */
export async function rebuildConnectorDiscovery(): Promise<number> {
  const banks = await withPlatform(async (tx) => {
    const tenants = await tx.connector.findMany({ where: { status: "ACTIVE" }, distinct: ["tenantId"], select: { tenantId: true } });
    const due: string[] = [];
    for (const { tenantId } of tenants) {
      const lastCollect = await tx.connectorJob.findFirst({
        where: { tenantId, type: "COLLECT", status: "SUCCEEDED", processedAt: { not: null } },
        orderBy: { processedAt: "desc" },
        select: { processedAt: true },
      });
      if (!lastCollect?.processedAt) continue;
      const lastBuild = await tx.discoveredApp.findFirst({ where: { tenantId }, orderBy: { updatedAt: "desc" }, select: { updatedAt: true } });
      const hasSoftware = (await tx.installedSoftware.count({ where: { tenantId }, take: 1 })) > 0;
      if (hasSoftware && (!lastBuild || lastBuild.updatedAt < lastCollect.processedAt)) due.push(tenantId);
    }
    return due;
  });
  for (const tenantId of banks) await rebuildDiscovered(tenantId);
  return banks.length;
}
