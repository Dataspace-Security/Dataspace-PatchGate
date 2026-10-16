import "server-only";
import type { Prisma } from "@prisma/client";
import type { z } from "zod";
import { withTenant } from "@/lib/tenancy";
import { log } from "@/lib/log";
import { handleWuScanResult } from "@/lib/winupdate/hooks";
import { onCacheJobFinished, onInstallJobFailed, onInstallJobOutcomeUnknown, onInstallJobSucceeded, scheduleInstallRetry } from "@/lib/deploy/connector-outcomes";
import { applyCollect, applyScan } from "./handlers-inventory";
import { applySyncAgents } from "./handlers-agents";
import { MAX_JOB_ATTEMPTS, isInstallJob, retryDelayMs } from "./policy";
import { enqueueJob } from "./queue";
import { jobPayloadSchemas, type JobResult, type JobType, type resultSchemas } from "./protocol";

/**
 * Applies a job's outcome to PatchGate's state (called from processJobResult, never inside the request).
 * Success → per-type handler. Retryable failure → a NEW job (new id, next generation, backoff); for
 * install jobs the pump queues it (LAN cap). Final failure → per-type consequences (deployment FAILED, …).
 * Install outcome unknown (the installer may have run) → never failed or retried: confirmed via inventory.
 * Idempotent: applying the same result twice (crash before processedAt was stored) schedules at most one
 * retry (ConnectorJob.retryOfJobId is unique) and status-guarded deployment updates change nothing.
 */

export interface StoredJob {
  id: string;
  tenantId: string;
  connectorId: string;
  type: JobType;
  payload: Prisma.JsonValue;
  attempts: number;
  deploymentId: string | null;
  changeRequestId: string | null;
  notBefore: Date;
  expiresAt: Date;
  deliveredAt: Date | null;
}

type ResultOf<T extends JobType> = z.infer<(typeof resultSchemas)[T]>;

export async function applyJobOutcome(job: StoredJob, res: JobResult, now: Date): Promise<void> {
  if (!res.ok) {
    if (res.outcomeUnknown && isInstallJob(job.type)) {
      log.warn("connector.job.outcome_unknown", { jobId: job.id, tenantId: job.tenantId, type: job.type, connectorId: job.connectorId, error: res.error });
      await onInstallJobOutcomeUnknown(job, res.error, now);
      return;
    }
    await onJobFailed(job, res.error, res.retryable, now);
    return;
  }
  const result = res.result;
  switch (job.type) {
    case "SYNC_AGENTS":
      await applySyncAgents(job, result as ResultOf<"SYNC_AGENTS">, now);
      return;
    case "SCAN":
      await applyScan(job, result as ResultOf<"SCAN">, now);
      return;
    case "COLLECT":
      await applyCollect(job, result as ResultOf<"COLLECT">, now);
      return;
    case "DEPLOY_WINDOWS":
    case "DEPLOY_PACKAGE":
    case "WU_INSTALL":
      await onInstallJobSucceeded(job, result);
      return;
    case "CACHE_PACKAGE":
      await onCacheJobFinished(job, { ok: true, result: result as ResultOf<"CACHE_PACKAGE"> });
      return;
    case "RESET_APPROVALS":
      log.info("connector.reset_approvals.done", { jobId: job.id, tenantId: job.tenantId, reset: (result as ResultOf<"RESET_APPROVALS">).reset });
      return;
    case "WU_SCAN":
      await withTenant(job.tenantId, (tx) => handleWuScanResult(tx, { tenantId: job.tenantId, connectorId: job.connectorId, jobId: job.id }, result as ResultOf<"WU_SCAN">), {
        timeoutMs: 120_000,
      });
      return;
    default: {
      const never: never = job.type;
      throw new Error(`no handler for job type ${String(never)}`);
    }
  }
}

/**
 * Retry window for a failed job: deployments keep their maintenance-window end; other jobs get a fresh
 * validity period of the same length as the original.
 */
function retryTimes(job: StoredJob, now: Date): { notBefore: Date; expiresAt: Date } | null {
  if (!Object.hasOwn(jobPayloadSchemas, job.type)) return null;
  const notBefore = new Date(now.getTime() + retryDelayMs(job.attempts));
  const expiresAt = isInstallJob(job.type) || job.deploymentId ? job.expiresAt : new Date(notBefore.getTime() + Math.max(15 * 60_000, job.expiresAt.getTime() - job.notBefore.getTime()));
  // Need a meaningful amount of time left to run.
  return expiresAt.getTime() - notBefore.getTime() >= 5 * 60_000 ? { notBefore, expiresAt } : null;
}

async function onJobFailed(job: StoredJob, error: string, retryable: boolean, now: Date): Promise<void> {
  const generation = job.attempts + 1;
  const times = retryable && generation < MAX_JOB_ATTEMPTS ? retryTimes(job, now) : null;
  if (times && isInstallJob(job.type) && job.deploymentId) {
    // The pump queues the retry when it is due, inside the connector's install cap.
    await scheduleInstallRetry(job, error, times.notBefore, generation);
    log.info("connector.job.retry_scheduled", { jobId: job.id, tenantId: job.tenantId, type: job.type, generation, notBefore: times.notBefore, error, via: "pump" });
    return;
  }
  if (times) {
    const retryId = await enqueueRetryOnce(job, times, generation, now);
    log.info("connector.job.retry_scheduled", { jobId: job.id, tenantId: job.tenantId, retryJobId: retryId, type: job.type, generation, notBefore: times.notBefore, error });
    return;
  }
  const final = retryable ? `${error} (gave up after ${generation} attempt(s))` : error;
  log.warn("connector.job.failed", { jobId: job.id, tenantId: job.tenantId, type: job.type, connectorId: job.connectorId, error: final });
  if (isInstallJob(job.type)) {
    await onInstallJobFailed(job, final, now);
  } else if (job.type === "CACHE_PACKAGE") {
    await onCacheJobFinished(job, { ok: false, error: final });
  }
  // SYNC / SCAN / COLLECT / WU_SCAN / RESET: nothing to undo; the schedules try again on their next round.
}

/** Queue the retry of `job` unless one exists already (idempotency key retryOfJobId). */
async function enqueueRetryOnce(job: StoredJob, times: { notBefore: Date; expiresAt: Date }, generation: number, now: Date): Promise<string> {
  return withTenant(job.tenantId, async (tx) => {
    // Serialise concurrent appliers of the same result; the unique index is the last line of defence.
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(4242005, hashtext(${job.id}))`;
    const existing = await tx.connectorJob.findFirst({ where: { retryOfJobId: job.id, tenantId: job.tenantId }, select: { id: true } });
    if (existing) return existing.id;
    const retry = await enqueueJob(
      tx,
      {
        tenantId: job.tenantId,
        connectorId: job.connectorId,
        type: job.type,
        payload: job.payload as never,
        notBefore: times.notBefore,
        expiresAt: times.expiresAt,
        deploymentId: job.deploymentId,
        changeRequestId: job.changeRequestId,
        attempts: generation,
        retryOfJobId: job.id,
      },
      now,
    );
    return retry.id;
  });
}
