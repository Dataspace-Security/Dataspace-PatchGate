import "server-only";
import type { Prisma } from "@prisma/client";
import type { z } from "zod";
import { appendAudit } from "@/lib/audit/service";
import { withTenant, type Tx } from "@/lib/tenancy";
import { log } from "@/lib/log";
import { handleWuInstallResult } from "@/lib/winupdate/hooks";
import { enqueueJob, type ExpiredJob } from "@/lib/connector/queue";
import { TACTICAL_MESSAGING_DOWN_NOTE, isTacticalNatsDown } from "@/lib/connector/policy";
import type { resultSchemas } from "@/lib/connector/protocol";
import type { StoredJob } from "@/lib/connector/handlers";
import { AuditBuffer, WAITING_NOTE_PREFIX, expectedGuidsOfJob, finish, installTypes, progressOf, stopRingIfFailing } from "./connector-state";

/**
 * Consequences of connector job outcomes for deployments (called from processJobResult via
 * applyJobOutcome, and from the worker's expiry sweep). Every handler is idempotent: a result applied a
 * second time (crash before processedAt was stored) changes nothing (status-guarded updates).
 */

type WuInstallResult = z.infer<(typeof resultSchemas)["WU_INSTALL"]>;

const RESET_APPROVALS_TTL_MS = 24 * 60 * 60_000;

/**
 * An install step succeeded: record it. The deployment's next step (or the next PC) is released by the
 * pump that runs once this result is marked processed (processJobResult).
 */
export async function onInstallJobSucceeded(job: StoredJob, result: unknown): Promise<void> {
  if (!job.deploymentId) {
    log.warn("deploy.install_result_without_deployment", { jobId: job.id, tenantId: job.tenantId, type: job.type });
    return;
  }
  const deploymentId = job.deploymentId;
  await withTenant(job.tenantId, async (tx) => {
    if (job.type === "WU_INSTALL") {
      const r = result as WuInstallResult;
      await handleWuInstallResult(tx, { tenantId: job.tenantId, connectorId: job.connectorId, jobId: job.id, deploymentId }, r);
      if (r.failed.length > 0) {
        const detail = r.failed.slice(0, 10).map((f) => `${f.updateId}: ${f.error}`).join("; ");
        // SENT too: a late result for a job whose window closed while it ran.
        await finish(tx, job.tenantId, deploymentId, ["SENDING", "SENT"], "FAILED", `Windows updates failed on the PC: ${detail}`, { kind: "INSTALL" });
        if (job.changeRequestId) await stopRingIfFailing(tx, job.tenantId, job.changeRequestId, new Date());
      }
    } else if (job.type === "DEPLOY_WINDOWS" && (result as { outcome?: string }).outcome === "NOTHING_TO_DO") {
      await tx.deployment.updateMany({
        where: { id: deploymentId, status: "SENDING" },
        data: { note: "Windows Update offered none of the approved updates on this PC (already installed or not applicable)" },
      });
    }
  });
}

/**
 * An install step failed for good: the deployment fails (also when it already moved to SENT because the
 * window closed while the job ran — a late failure must not end as a false success), approvals are
 * withdrawn, the ring is checked.
 */
export async function onInstallJobFailed(job: StoredJob, error: string, now: Date): Promise<void> {
  if (!job.deploymentId) return;
  const deploymentId = job.deploymentId;
  await withTenant(job.tenantId, async (tx) => {
    // Audit buffered: the chain lock is taken only after the RESET_APPROVALS job is signed.
    const audits = new AuditBuffer();
    const failed = await finish(tx, job.tenantId, deploymentId, ["SENDING", "SENT"], "FAILED", error, { kind: "INSTALL", audits });
    const agentId = (job.payload as { agentId?: unknown } | null)?.agentId;
    if (failed && job.type === "DEPLOY_WINDOWS" && typeof agentId === "string") {
      // Fail safe: nothing PatchGate approved may stay approved in Tactical.
      await enqueueJob(
        tx,
        { tenantId: job.tenantId, connectorId: job.connectorId, type: "RESET_APPROVALS", payload: { agentId }, expiresAt: new Date(now.getTime() + RESET_APPROVALS_TTL_MS), deploymentId },
        now,
      );
    }
    await audits.flush(tx);
    if (job.changeRequestId) await stopRingIfFailing(tx, job.tenantId, job.changeRequestId, now);
  });
}

/**
 * A retryable install failure: the retry is NOT queued here — the pump queues it (respecting
 * maxConcurrentInstalls) once `retryAt` has passed. Idempotent (status-guarded update).
 */
export async function scheduleInstallRetry(job: StoredJob, error: string, retryAt: Date, generation: number): Promise<void> {
  if (!job.deploymentId) return;
  const deploymentId = job.deploymentId;
  await withTenant(job.tenantId, (tx) =>
    tx.deployment.updateMany({
      where: { id: deploymentId, tenantId: job.tenantId, status: "SENDING" },
      data: {
        nextAttemptAt: retryAt,
        // Tactical's NATS bus down at the site: say so plainly (the details are in the job + the connector alert).
        note: (isTacticalNatsDown(error) ? `${TACTICAL_MESSAGING_DOWN_NOTE} (retry ${generation} scheduled)` : `retry ${generation} scheduled after: ${error}`).slice(0, 2000),
      },
    }),
  );
}

/** Move a SENDING deployment to SENT for confirmation via inventory (outcome of its last job unknown). */
async function toConfirmation(tx: Tx, tenantId: string, deploymentId: string, job: { type: string; payload: Prisma.JsonValue }, note: string, now: Date): Promise<boolean> {
  const progress = await progressOf(tx, deploymentId);
  const targetGuids = [...new Set([...progress.approvedGuids, ...expectedGuidsOfJob(job.type, job.payload)])];
  const { count } = await tx.deployment.updateMany({
    where: { id: deploymentId, tenantId, status: "SENDING" },
    data: { status: "SENT", startedAt: now, targetGuids, note },
  });
  return count === 1;
}

/**
 * The connector could not tell whether the install ran (timeout / connection lost while the installer was
 * running). Never failed and never retried blindly (no second installer on the PC): the deployment goes
 * to SENT and is confirmed — or timed out — from collected inventory. Not a ring-stop failure.
 */
export async function onInstallJobOutcomeUnknown(job: StoredJob, error: string, now: Date): Promise<void> {
  if (!job.deploymentId) return;
  const deploymentId = job.deploymentId;
  await withTenant(job.tenantId, async (tx) => {
    const moved = await toConfirmation(tx, job.tenantId, deploymentId, job, `outcome unknown (${error.slice(0, 300)}); confirming via inventory`, now);
    if (moved) {
      await appendAudit(
        {
          tenantId: job.tenantId,
          actor: "system",
          action: "deployment.outcome_unknown",
          entity: "Deployment",
          entityId: deploymentId,
          payload: { jobId: job.id, type: job.type, error: error.slice(0, 500), via: "connector" },
        },
        tx,
      );
    }
  });
}

type CacheOutcome = { ok: true; result: z.infer<(typeof resultSchemas)["CACHE_PACKAGE"]> } | { ok: false; error: string };

/**
 * Site cache result: a mismatching hash/size is a failure. On success, deployments of that connector that
 * were waiting for the cache are made due at once (they were parked with a later nextAttemptAt).
 */
export async function onCacheJobFinished(job: StoredJob, outcome: CacheOutcome): Promise<void> {
  const pkg = (job.payload as { package?: { sha256?: string; size?: number; wingetId?: string; version?: string } } | null)?.package;
  if (outcome.ok && (outcome.result.sha256 !== pkg?.sha256 || outcome.result.size !== pkg?.size)) {
    await withTenant(job.tenantId, (tx) =>
      tx.connectorJob.update({ where: { id: job.id }, data: { status: "FAILED", error: "cached file does not match the package (SHA-256/size)" } }),
    );
    log.error("connector.cache.mismatch", { jobId: job.id, tenantId: job.tenantId, connectorId: job.connectorId });
  } else if (!outcome.ok) {
    log.warn("connector.cache.failed", { jobId: job.id, tenantId: job.tenantId, connectorId: job.connectorId, package: `${pkg?.wingetId ?? "?"} ${pkg?.version ?? "?"}`, error: outcome.error });
  } else {
    const now = new Date();
    await withTenant(job.tenantId, (tx) =>
      tx.deployment.updateMany({
        where: { tenantId: job.tenantId, connectorId: job.connectorId, status: { in: ["QUEUED", "SENDING"] }, nextAttemptAt: { gt: now }, note: { startsWith: WAITING_NOTE_PREFIX } },
        data: { nextAttemptAt: now },
      }),
    );
  }
}

/**
 * Expired install jobs: undelivered → back to the queue (next window); delivered (it may be running on the
 * PC) → SENT for inventory confirmation, keeping the expected Windows updates as confirmation targets
 * (an empty target list would confirm a Windows install that never happened).
 */
export async function onJobsExpired(expired: readonly ExpiredJob[], now = new Date()): Promise<void> {
  for (const j of expired) {
    if (!j.deploymentId || !(installTypes as string[]).includes(j.type)) continue;
    const deploymentId = j.deploymentId;
    try {
      await withTenant(j.tenantId, async (tx) => {
        if (j.delivered) {
          const job = await tx.connectorJob.findFirst({ where: { id: j.id, tenantId: j.tenantId }, select: { type: true, payload: true } });
          await toConfirmation(tx, j.tenantId, deploymentId, job ?? { type: j.type, payload: null }, "no result before the maintenance window closed; outcome unknown — confirming via inventory", now);
        } else {
          await tx.deployment.updateMany({
            where: { id: deploymentId, tenantId: j.tenantId, status: "SENDING" },
            data: { status: "QUEUED", claimedAt: null, nextAttemptAt: now, note: "maintenance window ended before the connector started the install; re-queued for the next window" },
          });
        }
      });
    } catch (err: unknown) {
      log.error("deploy.expired_job_failed", { jobId: j.id, tenantId: j.tenantId, connectorId: j.connectorId, deploymentId, err });
    }
  }
}
