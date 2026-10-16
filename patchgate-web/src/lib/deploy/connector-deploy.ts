import "server-only";
import { Prisma, type DeploymentStatus } from "@prisma/client";
import { withPlatform, withTenant, type Tx } from "@/lib/tenancy";
import { log } from "@/lib/log";
import { enqueueJob } from "@/lib/connector/queue";
import { installSlots, isOnline, staggerOffsetMs } from "@/lib/connector/policy";
import { MAX_JOB_LIFETIME_MS } from "@/lib/connector/protocol";
import { CacheView, ensurePackageCached } from "./connector-cache";
import { PackageSizer, WindowsUpdatesNotReadyError, crPlanInclude, planEndpointSteps, type CrForPlan, type PlannedStep } from "./connector-plan";
import { AuditBuffer, WAITING_NOTE_PREFIX, finish, installTypes, progressOf, stopRingIfFailing } from "./connector-state";
import { currentWindow } from "./window";

export { stopRingIfFailing } from "./connector-state";
export { onCacheJobFinished, onInstallJobFailed, onInstallJobOutcomeUnknown, onInstallJobSucceeded, onJobsExpired } from "./connector-outcomes";

/**
 * Deployments for banks served by site connectors (the job producer that replaces direct Tactical calls).
 *
 * Maker-checker and maintenance windows are unchanged: only APPROVED → DEPLOYING change requests
 * (startDeployment) are delivered, only to the endpoints snapshotted at submission, and only inside their
 * window. Per endpoint, the install steps (connector-plan.ts) run one job at a time on its connector.
 *
 * LAN PROTECTION (ARCHITECTURE-HOSTED §2A):
 *  - per connector, never more in-flight install jobs (QUEUED + DELIVERED DEPLOY_* / WU_INSTALL) than
 *    Connector.maxConcurrentInstalls — retries included (the pump queues them, see scheduleInstallRetry);
 *    a cluster-wide advisory lock per connector makes the count + insert atomic across web instances.
 *  - first steps get a random notBefore inside the window (staggerOffsetMs), jobs expire at the window end
 *    (never later than MAX_JOB_LIFETIME_MS after notBefore — connectors refuse longer-lived jobs).
 *  - packages are cached at the site ONCE (CACHE_PACKAGE) before any PC is told to install them.
 *  - a ring whose INSTALL failure rate exceeds 20 % after ≥ 10 results is stopped (connector-state.ts).
 *  - offline connectors get no new work; queued jobs wait.
 *
 * ROBUSTNESS / SCALE:
 *  - every deployment is advanced inside its own SAVEPOINT: an unexpected error fails THAT deployment
 *    (kind INTERNAL, with a note) and the pump continues — one poison deployment never blocks a connector.
 *  - candidates come from Deployment(connectorId, status, nextAttemptAt); deployments that wait (cache,
 *    files, window) are parked with a later nextAttemptAt so they never starve the ones behind them.
 *  - audit events are buffered and appended at the end of the pump transaction (short chain-lock hold).
 */

const BUSY_RETRY_MS = 5 * 60_000;
const OUTSIDE_WINDOW_RETRY_MS = 15 * 60_000;
/** Deployments waiting for the site cache / Windows update files are looked at again after this. */
const WAIT_RETRY_MS = 2 * 60_000;
/** Deployments without a maintenance window: jobs are valid this long. */
const NO_WINDOW_TTL_MS = 6 * 60 * 60_000;
/** A job needs at least this much time before its expiry to be worth sending. */
const MIN_RUN_MS = 5 * 60_000;
const PUMP_TX_TIMEOUT_MS = 60_000;
const PUMP_LOCK = 4_242_004;
/** How many queued deployments one pump looks at beyond the free slots (some may wait for the cache). */
const CANDIDATE_FACTOR = 3;
const MAX_CANDIDATES = 1000;

type DeploymentRow = Prisma.DeploymentGetPayload<{ include: { endpoint: true; changeRequest: { include: typeof crPlanInclude } } }>;
const deploymentInclude = { endpoint: true, changeRequest: { include: crPlanInclude } } as const;

function windowEnd(cr: CrForPlan, now: Date): Date | null {
  if (!cr.window) return new Date(now.getTime() + NO_WINDOW_TTL_MS);
  return currentWindow(cr.window, now)?.end ?? null;
}

async function inFlightInstalls(tx: Tx, connectorId: string): Promise<number> {
  return tx.connectorJob.count({ where: { connectorId, type: { in: installTypes }, status: { in: ["QUEUED", "DELIVERED"] } } });
}

type AdvanceOutcome = "pending" | "enqueued" | "waiting-cache" | "sent" | "failed" | "outside-window";

interface AdvanceCtx {
  connector: { id: string; tenantId: string; maxConcurrentInstalls: number };
  sizer: PackageSizer;
  cache: CacheView;
  audits: AuditBuffer;
  now: Date;
}

/** Park a deployment that waits (cache, Windows update files, window) so later candidates get their turn. */
async function park(tx: Tx, d: DeploymentRow, ctx: AdvanceCtx, delayMs: number, note: string | null): Promise<void> {
  await tx.deployment.updateMany({
    where: { id: d.id, tenantId: d.tenantId, status: d.status },
    data: { nextAttemptAt: new Date(ctx.now.getTime() + delayMs), ...(note !== null ? { note: note.slice(0, 2000) } : {}) },
  });
}

/** Ensure every package of the remaining steps is cached at the site (prefetch for the whole plan). */
async function cacheReadiness(tx: Tx, steps: readonly PlannedStep[], ctx: AdvanceCtx): Promise<"ready" | "pending" | { failed: string }> {
  let pending = false;
  const seen = new Set<string>();
  for (const s of steps) {
    for (const pkg of s.cacheNeeds) {
      if (seen.has(pkg.sha256)) continue;
      seen.add(pkg.sha256);
      const st = await ensurePackageCached(tx, ctx.connector, pkg, ctx.now, ctx.cache);
      if (st.state === "failed") return { failed: `${pkg.wingetId} ${pkg.version} could not be cached at the site: ${st.error}` };
      if (st.state === "pending") pending = true;
    }
  }
  return pending ? "pending" : "ready";
}

/** Plan the remaining steps; waiting / planning failures are handled here. */
async function planRemaining(tx: Tx, d: DeploymentRow, ctx: AdvanceCtx, done: ReadonlySet<string>): Promise<PlannedStep[] | AdvanceOutcome> {
  try {
    return await planEndpointSteps(tx, d.tenantId, d.changeRequest, d.endpoint, ctx.sizer, done);
  } catch (err: unknown) {
    if (err instanceof WindowsUpdatesNotReadyError) {
      await park(tx, d, ctx, WAIT_RETRY_MS, `${WAITING_NOTE_PREFIX}Windows update files: ${err.reason}`);
      return "waiting-cache";
    }
    await finish(tx, d.tenantId, d.id, d.status, "FAILED", err instanceof Error ? err.message : "planning failed", { kind: "PLANNING", audits: ctx.audits });
    return "failed";
  }
}

/**
 * Move one SENDING deployment forward: next undone step → job (if its packages are cached), or SENT when
 * every step is done. The caller holds the connector's pump lock and has checked the install slot.
 */
async function advance(tx: Tx, d: DeploymentRow, ctx: AdvanceCtx): Promise<AdvanceOutcome> {
  const tenantId = d.tenantId;
  // Progress FIRST: steps that already ran are never planned again (C1: a Windows step that installed
  // everything must not turn into "Windows updates not ready" for ever).
  const progress = await progressOf(tx, d.id);
  if (progress.pending) return "pending";
  const planned = await planRemaining(tx, d, ctx, progress.done);
  if (!Array.isArray(planned)) return planned;
  if (planned.length === 0) {
    const targetGuids = [...new Set(progress.approvedGuids)];
    await tx.deployment.updateMany({
      where: { id: d.id, tenantId, status: "SENDING" },
      data: { status: "SENT", startedAt: ctx.now, targetGuids, note: progress.anyJob ? null : "nothing to install on this PC" },
    });
    return "sent";
  }
  const end = windowEnd(d.changeRequest, ctx.now);
  if (!end) {
    await park(tx, d, ctx, OUTSIDE_WINDOW_RETRY_MS, null);
    return "outside-window";
  }

  const cache = await cacheReadiness(tx, planned, ctx);
  if (cache === "pending") {
    await park(tx, d, ctx, WAIT_RETRY_MS, `${WAITING_NOTE_PREFIX}the site cache`);
    return "waiting-cache";
  }
  if (cache !== "ready") {
    await finish(tx, tenantId, d.id, "SENDING", "FAILED", cache.failed, { kind: "CACHE", audits: ctx.audits });
    return "failed";
  }
  const next = planned[0];
  // Stagger only the first step of a deployment; later steps (and retries, whose backoff is already in
  // nextAttemptAt) follow directly.
  const notBefore = progress.anyJob ? ctx.now : new Date(ctx.now.getTime() + staggerOffsetMs(end.getTime() - ctx.now.getTime(), ctx.connector.maxConcurrentInstalls));
  const expiresAt = new Date(Math.min(end.getTime(), notBefore.getTime() + MAX_JOB_LIFETIME_MS));
  if (expiresAt.getTime() - notBefore.getTime() < MIN_RUN_MS) {
    await park(tx, d, ctx, OUTSIDE_WINDOW_RETRY_MS, null);
    return "outside-window";
  }
  await enqueueJob(
    tx,
    {
      tenantId,
      connectorId: ctx.connector.id,
      type: next.type,
      payload: next.payload,
      notBefore,
      expiresAt,
      deploymentId: d.id,
      changeRequestId: d.changeRequestId,
      attempts: progress.failedByStep.get(next.key) ?? 0,
    },
    ctx.now,
  );
  if (d.note?.startsWith(WAITING_NOTE_PREFIX) || d.note?.startsWith("retry ")) {
    await tx.deployment.updateMany({ where: { id: d.id, tenantId }, data: { note: null } });
  }
  return "enqueued";
}

/** Claim a QUEUED deployment (window, plan and cache checked first) and start its first undone step. */
async function startOne(tx: Tx, d: DeploymentRow, ctx: AdvanceCtx, result: PumpResult): Promise<AdvanceOutcome> {
  const { now } = ctx;
  if (!windowEnd(d.changeRequest, now)) {
    await park(tx, d, ctx, OUTSIDE_WINDOW_RETRY_MS, null);
    return "outside-window";
  }
  // A re-queued deployment (window ended before delivery) keeps the steps it already completed.
  const progress = await progressOf(tx, d.id);
  if (progress.pending) return "pending";
  const planned = await planRemaining(tx, d, ctx, progress.done);
  if (!Array.isArray(planned)) return planned;
  // Do not claim a PC before the site holds its packages: waiting deployments stay QUEUED.
  const cache = await cacheReadiness(tx, planned, ctx);
  if (cache === "pending") {
    await park(tx, d, ctx, WAIT_RETRY_MS, `${WAITING_NOTE_PREFIX}the site cache`);
    return "waiting-cache";
  }
  if (cache !== "ready") {
    await finish(tx, d.tenantId, d.id, "QUEUED", "FAILED", cache.failed, { kind: "CACHE", audits: ctx.audits });
    return "failed";
  }
  // Claim. The partial unique index allows one SENDING/SENT deployment per endpoint: a savepoint keeps a
  // unique violation from aborting the whole pump transaction.
  await tx.$executeRaw`SAVEPOINT claim_deployment`;
  try {
    const { count } = await tx.deployment.updateMany({
      where: { id: d.id, status: "QUEUED" },
      data: { status: "SENDING", attempts: { increment: 1 }, claimedAt: now, nextAttemptAt: now, note: null, connectorId: ctx.connector.id },
    });
    await tx.$executeRaw`RELEASE SAVEPOINT claim_deployment`;
    if (count !== 1) return "pending";
  } catch (err: unknown) {
    await tx.$executeRaw`ROLLBACK TO SAVEPOINT claim_deployment`;
    await tx.$executeRaw`RELEASE SAVEPOINT claim_deployment`;
    if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === "P2002") {
      await park(tx, d, ctx, BUSY_RETRY_MS, "endpoint busy with another change request");
      result.busy++;
      return "pending";
    }
    throw err;
  }
  return advance(tx, { ...d, status: "SENDING", nextAttemptAt: now, note: null }, ctx);
}

/**
 * Run one deployment's step inside a savepoint. An unexpected error (bad payload, signing problem, a
 * constraint, …) rolls back only this deployment's work, fails it with a note, and the pump continues.
 */
async function isolated(tx: Tx, d: DeploymentRow, ctx: AdvanceCtx, fn: () => Promise<AdvanceOutcome>): Promise<AdvanceOutcome> {
  const mark = ctx.audits.mark();
  await tx.$executeRaw`SAVEPOINT pump_deployment`;
  try {
    const o = await fn();
    await tx.$executeRaw`RELEASE SAVEPOINT pump_deployment`;
    return o;
  } catch (err: unknown) {
    await tx.$executeRaw`ROLLBACK TO SAVEPOINT pump_deployment`;
    await tx.$executeRaw`RELEASE SAVEPOINT pump_deployment`;
    ctx.audits.rollback(mark);
    const message = err instanceof Error ? err.message : "unexpected error";
    log.error("deploy.pump_deployment_failed", { deploymentId: d.id, connectorId: ctx.connector.id, err });
    const from: DeploymentStatus[] = ["QUEUED", "SENDING"];
    await finish(tx, d.tenantId, d.id, from, "FAILED", `could not produce the install job: ${message}`.slice(0, 2000), { kind: "INTERNAL", audits: ctx.audits });
    return "failed";
  }
}

// ---------------------------------------------------------------------------------------------
// Pump: release installs for one connector up to its cap
// ---------------------------------------------------------------------------------------------

export interface PumpResult {
  enqueued: number;
  sent: number;
  failed: number;
  waitingCache: number;
  busy: number;
  inFlight: number;
}

/** SENDING deployments of a connector that are due and have no install job in flight / unapplied. */
async function dueSending(tx: Tx, tenantId: string, connectorId: string, now: Date, limit: number): Promise<string[]> {
  const rows = await tx.$queryRaw<{ id: string }[]>`
    SELECT d."id" FROM "Deployment" d
      JOIN "ChangeRequest" c ON c."id" = d."changeRequestId" AND c."status" = 'DEPLOYING'
     WHERE d."tenantId" = ${tenantId} AND d."connectorId" = ${connectorId} AND d."status" = 'SENDING' AND d."nextAttemptAt" <= ${now}
       AND NOT EXISTS (
         SELECT 1 FROM "ConnectorJob" j
          WHERE j."deploymentId" = d."id" AND j."type" IN ('DEPLOY_WINDOWS', 'DEPLOY_PACKAGE', 'WU_INSTALL')
            AND (j."status" IN ('QUEUED', 'DELIVERED') OR (j."status" IN ('SUCCEEDED', 'FAILED') AND j."processedAt" IS NULL)))
     ORDER BY d."nextAttemptAt" ASC
     LIMIT ${limit}`;
  return rows.map((r) => r.id);
}

export async function pumpConnector(tenantId: string, connectorId: string, now = new Date()): Promise<PumpResult> {
  const result: PumpResult = { enqueued: 0, sent: 0, failed: 0, waitingCache: 0, busy: 0, inFlight: 0 };
  await withTenant(
    tenantId,
    async (tx) => {
      await tx.$executeRaw`SELECT pg_advisory_xact_lock(${PUMP_LOCK}::int4, hashtext(${connectorId}))`;
      const c = await tx.connector.findFirst({ where: { id: connectorId, tenantId }, select: { id: true, tenantId: true, status: true, lastSeenAt: true, maxConcurrentInstalls: true } });
      if (!c || c.status !== "ACTIVE" || !isOnline(c.lastSeenAt, now)) return; // offline: queued work waits
      const ctx: AdvanceCtx = { connector: c, sizer: new PackageSizer(), cache: await CacheView.load(tx, c.id), audits: new AuditBuffer(), now };
      let slots = installSlots(c.maxConcurrentInstalls, await inFlightInstalls(tx, c.id));
      const tally = (o: AdvanceOutcome) => {
        if (o === "enqueued") {
          result.enqueued++;
          slots--;
        } else if (o === "sent") result.sent++;
        else if (o === "failed") result.failed++;
        else if (o === "waiting-cache") result.waitingCache++;
      };

      // 1. Deployments already running on this connector whose last step finished (or whose retry is due).
      if (slots > 0) {
        const ids = await dueSending(tx, tenantId, c.id, now, Math.min(MAX_CANDIDATES, slots * CANDIDATE_FACTOR + 10));
        const running = ids.length > 0 ? await tx.deployment.findMany({ where: { id: { in: ids }, tenantId }, include: deploymentInclude }) : [];
        running.sort((a, b) => a.nextAttemptAt.getTime() - b.nextAttemptAt.getTime());
        for (const d of running) {
          if (slots <= 0) break;
          tally(await isolated(tx, d, ctx, () => advance(tx, d, ctx)));
        }
      }

      // 2. New deployments, oldest due first, while slots are free.
      if (slots > 0) {
        const candidates = await tx.deployment.findMany({
          where: { tenantId, connectorId: c.id, status: "QUEUED", nextAttemptAt: { lte: now }, changeRequest: { status: "DEPLOYING" } },
          orderBy: { nextAttemptAt: "asc" },
          take: Math.min(MAX_CANDIDATES, slots * CANDIDATE_FACTOR + 10),
          include: deploymentInclude,
        });
        for (const d of candidates) {
          if (slots <= 0) break;
          tally(await isolated(tx, d, ctx, () => startOne(tx, d, ctx, result)));
        }
      }
      result.inFlight = await inFlightInstalls(tx, c.id);
      await ctx.audits.flush(tx);
    },
    { timeoutMs: PUMP_TX_TIMEOUT_MS },
  );
  return result;
}

/** pumpConnector that never throws (used after results; the tick retries anyway). */
export async function pumpConnectorSafe(tenantId: string, connectorId: string, now = new Date()): Promise<PumpResult | null> {
  try {
    return await pumpConnector(tenantId, connectorId, now);
  } catch (err: unknown) {
    log.error("deploy.pump_failed", { tenantId, connectorId, err });
    return null;
  }
}

/** A PC no ACTIVE connector has reported for this long cannot be reached: its deployments fail. */
export const UNMANAGED_GRACE_MS = 2 * 60 * 60_000;

/**
 * Deployments of connector-backed banks whose PC is not (or no longer) managed by an ACTIVE connector —
 * agent gone from Tactical, connector revoked — would otherwise wait forever and block the change
 * request. After a grace period (the next SYNC may re-assign the PC) they are FAILED with a clear note.
 */
async function failUnmanaged(tx: Tx, tenantId: string, crId: string, now: Date): Promise<number> {
  const cutoff = new Date(now.getTime() - UNMANAGED_GRACE_MS);
  const stuck = await tx.deployment.findMany({
    where: {
      tenantId,
      changeRequestId: crId,
      status: "QUEUED",
      endpoint: {
        OR: [{ connectorId: null }, { connector: { status: "REVOKED" } }],
        AND: [{ OR: [{ lastSeenAt: null }, { lastSeenAt: { lt: cutoff } }] }],
      },
    },
    select: { id: true },
  });
  const audits = new AuditBuffer();
  let failed = 0;
  for (const d of stuck) {
    if (await finish(tx, tenantId, d.id, "QUEUED", "FAILED", "no active site connector manages this PC (not reported by any connector for 2 h)", { kind: "UNMANAGED", audits })) failed++;
  }
  await audits.flush(tx);
  return failed;
}

/** Worker step: ring-stop checks, then release installs for every online connector. */
export async function produceConnectorDeployments(now = new Date()): Promise<{ connectors: number; enqueued: number; stopped: number }> {
  const { connectors, crs } = await withPlatform(async (tx) => ({
    connectors: await tx.connector.findMany({ where: { status: "ACTIVE", tenant: { active: true } }, select: { id: true, tenantId: true, lastSeenAt: true } }),
    crs: await tx.changeRequest.findMany({
      where: { status: "DEPLOYING", tenant: { connectors: { some: { status: "ACTIVE" } } } },
      select: { id: true, tenantId: true },
    }),
  }));
  let stopped = 0;
  for (const cr of crs) {
    try {
      stopped += await withTenant(cr.tenantId, async (tx) => (await stopRingIfFailing(tx, cr.tenantId, cr.id, now)) + (await failUnmanaged(tx, cr.tenantId, cr.id, now)));
    } catch (err: unknown) {
      log.error("deploy.ring_check_failed", { tenantId: cr.tenantId, crId: cr.id, err });
    }
  }
  let enqueued = 0;
  for (const c of connectors) {
    if (!isOnline(c.lastSeenAt, now)) continue;
    const r = await pumpConnectorSafe(c.tenantId, c.id, now);
    enqueued += r?.enqueued ?? 0;
  }
  return { connectors: connectors.length, enqueued, stopped };
}
