import "server-only";
import { withPlatform, withTenant, type Tx } from "@/lib/tenancy";
import { log } from "@/lib/log";
import { activeConnectors, type ActiveConnector } from "@/lib/connector/routing";
import { enqueueJob } from "@/lib/connector/queue";
import { MAX_AGENTS_PER_JOB, type JobPackage } from "@/lib/connector/protocol";
import { ensurePackageCached } from "@/lib/deploy/connector-cache";
import { rebuildDiscovered } from "@/lib/discovery/service";
import { wuScanCab } from "@/lib/winupdate/hooks";

/**
 * Inventory schedules for connector-backed banks (the connector replaces direct Tactical reads):
 *   SYNC_AGENTS  hourly per connector
 *   SCAN         daily per PC, batches of ≤ 200 agents
 *   COLLECT      every 6 h per PC (updates + software + agent version), batches of ≤ 200
 *   WU_SCAN      daily per connector when the winupdate pipeline has a verified offline scan catalog
 *                (the cab is cached at the site first with CACHE_PACKAGE)
 * Offline connectors get no new periodic work: what is queued waits, nothing piles up.
 * PCs are marked when their batch is scheduled (lastScanRequestedAt / ingestAttemptAt), so a batch is
 * never scheduled twice while its result is outstanding.
 */

export const SYNC_INTERVAL_MS = 60 * 60_000;
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
} as const;

export interface ScheduleSummary {
  sync: number;
  scan: number;
  collect: number;
  wuScan: number;
  skippedOffline: number;
}

async function scheduleSync(tx: Tx, c: ActiveConnector, now: Date): Promise<number> {
  const recent = await tx.connectorJob.count({
    where: {
      connectorId: c.id,
      type: "SYNC_AGENTS",
      OR: [{ status: { in: ["QUEUED", "DELIVERED"] } }, { createdAt: { gt: new Date(now.getTime() - SYNC_INTERVAL_MS) }, status: { not: "CANCELLED" } }],
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

async function scheduleWuScan(tx: Tx, c: ActiveConnector, cab: JobPackage, now: Date): Promise<number> {
  const recent = await tx.connectorJob.count({
    where: { connectorId: c.id, type: "WU_SCAN", createdAt: { gt: new Date(now.getTime() - WU_SCAN_INTERVAL_MS) }, status: { not: "CANCELLED" } },
  });
  if (recent > 0) return 0;
  // The site must hold the signed scan catalog before any PC can scan against it.
  const cache = await ensurePackageCached(tx, c, cab, now);
  if (cache.state !== "cached") return 0;
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
  const summary: ScheduleSummary = { sync: 0, scan: 0, collect: 0, wuScan: 0, skippedOffline: 0 };
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
