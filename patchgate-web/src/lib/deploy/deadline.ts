import "server-only";
import { withPlatform, withTenant } from "@/lib/tenancy";
import { log } from "@/lib/log";
import { cancelQueuedJobs } from "@/lib/connector/queue";
import { AuditBuffer, finish, installTypes } from "./connector-state";
import { enqueueNotification } from "@/lib/notify/enqueue";

/**
 * Change-request deployment deadline (M3). Without it a deployment can wait for ever — Windows update
 * files never verified, a window that never opens, an online-but-silent connector, a PC that stays busy —
 * and its change request never finalises. When the deadline passes, everything NOT STARTED is TIMED_OUT
 * (kind DEADLINE, not a ring-stop failure) with a clear note; work already running on a PC (a delivered
 * job, a SENT deployment awaiting confirmation) finishes or times out on its own.
 *
 * Configurable with DEPLOY_DEADLINE_DAYS (1 – 90, default 14), fixed per change request when it starts.
 */

export const DEFAULT_DEPLOY_DEADLINE_DAYS = 14;
const MIN_DAYS = 1;
const MAX_DAYS = 90;
const DAY_MS = 24 * 60 * 60_000;

export function deployDeadlineDays(raw: string | undefined = process.env.DEPLOY_DEADLINE_DAYS): number {
  if (raw === undefined || raw.trim() === "") return DEFAULT_DEPLOY_DEADLINE_DAYS;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < MIN_DAYS || n > MAX_DAYS) {
    log.warn("deploy.deadline_days_invalid", { value: raw.slice(0, 20), using: DEFAULT_DEPLOY_DEADLINE_DAYS });
    return DEFAULT_DEPLOY_DEADLINE_DAYS;
  }
  return n;
}

export function deployDeadlineFrom(start: Date, days = deployDeadlineDays()): Date {
  return new Date(start.getTime() + days * DAY_MS);
}

const CHUNK = 1_000;

/** Time out what one change request has not started by its deadline. Returns the deployments timed out. */
async function expireChangeRequest(tenantId: string, crId: string, deadline: Date, now: Date): Promise<number> {
  const note = `deployment deadline (${deadline.toISOString()}) passed before the install started`;
  return withTenant(
    tenantId,
    async (tx) => {
      const cancelled = await cancelQueuedJobs(tx, { tenantId, changeRequestId: crId, type: { in: installTypes } }, "deployment deadline passed", now);
      const queued = await tx.deployment.updateMany({
        where: { tenantId, changeRequestId: crId, status: "QUEUED" },
        data: { status: "TIMED_OUT", error: note, note, failureKind: "DEADLINE", finishedAt: now },
      });
      // SENDING without anything running on a PC (waiting for cache / files / window / retry).
      const audits = new AuditBuffer();
      let sending = 0;
      for (;;) {
        const rows = await tx.$queryRaw<{ id: string }[]>`
          SELECT d."id" FROM "Deployment" d
           WHERE d."tenantId" = ${tenantId} AND d."changeRequestId" = ${crId} AND d."status" = 'SENDING' AND d."connectorId" IS NOT NULL
             AND NOT EXISTS (SELECT 1 FROM "ConnectorJob" j WHERE j."deploymentId" = d."id" AND (j."status" = 'DELIVERED' OR (j."status" IN ('SUCCEEDED', 'FAILED') AND j."processedAt" IS NULL)))
           LIMIT ${CHUNK}`;
        let progressed = 0;
        for (const r of rows) if (await finish(tx, tenantId, r.id, "SENDING", "TIMED_OUT", note, { kind: "DEADLINE", audits })) progressed++;
        sending += progressed;
        if (rows.length < CHUNK || progressed === 0) break;
      }
      audits.push({
        tenantId,
        actor: "system",
        action: "change_request.deadline_reached",
        entity: "ChangeRequest",
        entityId: crId,
        payload: { deadline: deadline.toISOString(), timedOutQueued: queued.count, timedOutSending: sending, cancelledJobs: cancelled },
      });
      await audits.flush(tx);
      if (queued.count + sending > 0) await enqueueNotification(tx, { event: "CR_DEADLINE", tenantId, crId, deadline, timedOut: queued.count + sending });
      return queued.count + sending;
    },
    { timeoutMs: 120_000 },
  );
}

/** Worker step: apply the deadline of every DEPLOYING change request that passed it. */
export async function enforceDeployDeadlines(now = new Date()): Promise<{ changeRequests: number; timedOut: number }> {
  const due = await withPlatform((tx) =>
    tx.changeRequest.findMany({
      where: { status: "DEPLOYING", deployDeadlineAt: { lte: now }, deployments: { some: { status: { in: ["QUEUED", "SENDING"] } } } },
      select: { id: true, tenantId: true, deployDeadlineAt: true },
      take: 100,
    }),
  );
  let timedOut = 0;
  for (const cr of due) {
    try {
      timedOut += await expireChangeRequest(cr.tenantId, cr.id, cr.deployDeadlineAt!, now);
    } catch (err: unknown) {
      log.error("deploy.deadline_failed", { tenantId: cr.tenantId, crId: cr.id, err });
    }
  }
  if (timedOut > 0) log.warn("deploy.deadline_reached", { changeRequests: due.length, timedOut });
  return { changeRequests: due.length, timedOut };
}
