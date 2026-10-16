import "server-only";
import type { DeploymentFailureKind, DeploymentStatus, Prisma } from "@prisma/client";
import { appendAudit, type AuditInput } from "@/lib/audit/service";
import type { Tx } from "@/lib/tenancy";
import { log } from "@/lib/log";
import { cancelQueuedJobs } from "@/lib/connector/queue";
import { INSTALL_JOB_TYPES, ringShouldStop } from "@/lib/connector/policy";
import type { JobType } from "@/lib/connector/protocol";
import { stepKeyOfJob } from "./connector-plan";
import { enqueueNotification } from "@/lib/notify/enqueue";

/**
 * Shared deployment state helpers of the connector pipeline (pump, job outcomes, ring stop, deadline).
 */

export const installTypes = INSTALL_JOB_TYPES as unknown as JobType[];

/** Notes of deployments that wait for the site cache / Windows update files start with this. */
export const WAITING_NOTE_PREFIX = "waiting for ";

/**
 * Audit events collected during a long transaction and appended at its END: appendAudit takes the bank
 * chain's advisory lock, which is then held only for the last moments of the transaction instead of for
 * the whole pump (other writers of that bank's chain would otherwise queue behind it).
 */
export class AuditBuffer {
  private entries: AuditInput[] = [];

  push(e: AuditInput): void {
    this.entries.push(e);
  }

  /** Savepoint support: entries pushed after `mark()` are dropped by `rollback(mark)`. */
  mark(): number {
    return this.entries.length;
  }

  rollback(mark: number): void {
    this.entries = this.entries.slice(0, mark);
  }

  get size(): number {
    return this.entries.length;
  }

  async flush(tx: Tx): Promise<void> {
    const pending = this.entries;
    this.entries = [];
    for (const e of pending) await appendAudit(e, tx);
  }
}

export interface FinishOptions {
  kind?: DeploymentFailureKind;
  note?: string;
  /** Buffer the audit (flushed by the caller before commit) instead of appending it now. */
  audits?: AuditBuffer;
  extra?: Prisma.InputJsonValue;
}

/** Move a deployment to a terminal state (only from `from`), audited on the bank's chain. */
export async function finish(
  tx: Tx,
  tenantId: string,
  id: string,
  from: DeploymentStatus | readonly DeploymentStatus[],
  status: "SUCCEEDED" | "FAILED" | "TIMED_OUT",
  error: string | null,
  opts: FinishOptions = {},
): Promise<boolean> {
  const fromList = typeof from === "string" ? [from] : [...from];
  const kind = status === "SUCCEEDED" ? null : (opts.kind ?? "INSTALL");
  const { count } = await tx.deployment.updateMany({
    where: { id, tenantId, status: { in: fromList } },
    data: { status, error: error?.slice(0, 2000) ?? null, failureKind: kind, finishedAt: new Date(), ...(opts.note ? { note: opts.note.slice(0, 2000) } : {}) },
  });
  if (count === 1) {
    const event: AuditInput = {
      tenantId,
      actor: "system",
      action: `deployment.${status.toLowerCase()}`,
      entity: "Deployment",
      entityId: id,
      payload: { error, via: "connector", ...(kind ? { kind } : {}), ...(opts.extra !== undefined ? { detail: opts.extra } : {}) },
    };
    if (opts.audits) opts.audits.push(event);
    else await appendAudit(event, tx);
  }
  return count === 1;
}

export interface StepProgress {
  /** an install job is queued / running, or its result is not applied yet */
  pending: boolean;
  /** step keys that succeeded */
  done: Set<string>;
  anyJob: boolean;
  /** GUIDs Tactical approved (DEPLOY_WINDOWS results) */
  approvedGuids: string[];
  /** failed jobs per step key (= the next job's generation) */
  failedByStep: Map<string, number>;
}

/**
 * Where a deployment's install steps stand. A job whose result was accepted but not applied yet (FAILED or
 * SUCCEEDED with processedAt = null) counts as PENDING: until the handler ran we do not know whether it
 * will be retried, so the step must not be queued a second time.
 */
export async function progressOf(tx: Tx, deploymentId: string): Promise<StepProgress> {
  const jobs = await tx.connectorJob.findMany({
    where: { deploymentId, type: { in: installTypes } },
    select: { type: true, status: true, payload: true, result: true, processedAt: true },
  });
  const done = new Set<string>();
  const approvedGuids: string[] = [];
  const failedByStep = new Map<string, number>();
  let pending = false;
  for (const j of jobs) {
    if (j.status === "QUEUED" || j.status === "DELIVERED") pending = true;
    if ((j.status === "SUCCEEDED" || j.status === "FAILED") && j.processedAt === null) pending = true;
    const key = stepKeyOfJob(j.type, j.payload);
    if (j.status === "FAILED" && key) failedByStep.set(key, (failedByStep.get(key) ?? 0) + 1);
    if (j.status !== "SUCCEEDED") continue;
    if (key) done.add(key);
    if (j.type === "DEPLOY_WINDOWS") {
      const r = (j.result as { result?: { approved?: unknown } } | null)?.result?.approved;
      if (Array.isArray(r)) approvedGuids.push(...r.filter((g): g is string => typeof g === "string"));
    }
  }
  return { pending, done, anyJob: jobs.length > 0, approvedGuids, failedByStep };
}

/** Windows updates an install job was meant to install (confirmation targets when its outcome is unknown). */
export function expectedGuidsOfJob(type: string, payload: Prisma.JsonValue): string[] {
  const p = payload as { guids?: unknown; updates?: unknown } | null;
  if (type === "DEPLOY_WINDOWS" && Array.isArray(p?.guids)) return p.guids.filter((g): g is string => typeof g === "string");
  if (type === "WU_INSTALL" && Array.isArray(p?.updates)) {
    return p.updates.flatMap((u) => (typeof (u as { updateId?: unknown })?.updateId === "string" ? [(u as { updateId: string }).updateId] : []));
  }
  return [];
}

// ---------------------------------------------------------------------------------------------
// Ring stop
// ---------------------------------------------------------------------------------------------

/**
 * Ring-stop inputs of one change request. Successes include SENT (the install was reported started /
 * OK and awaits inventory confirmation) — confirmation lags hours behind failures, which arrive at once.
 * Failures are only INSTALL failures (incl. confirmation timeouts): planning / cache / deadline /
 * unmanaged-PC failures say nothing about whether the patch breaks PCs.
 */
export async function ringCounts(tx: Tx, tenantId: string, crId: string): Promise<{ succeeded: number; failed: number; notStarted: number }> {
  const counts = await tx.deployment.groupBy({ by: ["status", "failureKind"], where: { tenantId, changeRequestId: crId }, _count: { _all: true } });
  let succeeded = 0;
  let failed = 0;
  let notStarted = 0;
  for (const c of counts) {
    const n = c._count._all;
    if (c.status === "SUCCEEDED" || c.status === "SENT") succeeded += n;
    else if ((c.status === "FAILED" || c.status === "TIMED_OUT") && c.failureKind === "INSTALL") failed += n;
    else if (c.status === "QUEUED" || c.status === "SENDING") notStarted += n;
  }
  return { succeeded, failed, notStarted };
}

/** Stop a change request's rollout when too many installs fail. Returns how many deployments were stopped. */
export async function stopRingIfFailing(tx: Tx, tenantId: string, crId: string, now: Date): Promise<number> {
  const { succeeded, failed, notStarted } = await ringCounts(tx, tenantId, crId);
  if (!ringShouldStop(succeeded, failed) || notStarted === 0) return 0;

  const rate = Math.round((failed / (succeeded + failed)) * 100);
  const note = `ring stopped: ${failed} of ${succeeded + failed} installs failed (${rate} %); not started`;
  const audits = new AuditBuffer();
  // Jobs not yet picked up by the connector are withdrawn; delivered ones finish on the PC.
  const cancelled = await cancelQueuedJobs(tx, { tenantId, changeRequestId: crId, type: { in: installTypes } }, "ring stopped", now);
  const sending = await tx.deployment.findMany({ where: { tenantId, changeRequestId: crId, status: "SENDING" }, select: { id: true } });
  let stopped = 0;
  for (const d of sending) {
    const live = await tx.connectorJob.count({ where: { deploymentId: d.id, status: "DELIVERED" } });
    if (live === 0 && (await finish(tx, tenantId, d.id, "SENDING", "FAILED", note, { kind: "RING_STOPPED", audits }))) stopped++;
  }
  const queued = await tx.deployment.updateMany({
    where: { tenantId, changeRequestId: crId, status: "QUEUED" },
    data: { status: "FAILED", error: note, note, failureKind: "RING_STOPPED", finishedAt: now },
  });
  stopped += queued.count;
  audits.push({
    tenantId,
    actor: "system",
    action: "change_request.ring_stopped",
    entity: "ChangeRequest",
    entityId: crId,
    payload: { succeeded, failed, failureRatePct: rate, stoppedDeployments: stopped, cancelledJobs: cancelled },
  });
  await audits.flush(tx);
  if (stopped > 0) await enqueueNotification(tx, { event: "RING_STOPPED", tenantId, crId, succeeded, failed, failureRatePct: rate, stopped });
  log.warn("deploy.ring_stopped", { tenantId, crId, succeeded, failed, stopped });
  return stopped;
}
