import "server-only";
import { randomBytes } from "node:crypto";
import type { Prisma } from "@prisma/client";
import { withPlatform, withTenant, type Tx } from "@/lib/tenancy";
import { log } from "@/lib/log";
import { signJobEnvelope } from "./keys";
import { MAX_JOBS_PER_POLL, MAX_JOB_LIFETIME_MS, jobPayloadSchemas, type JobEnvelope, type JobPayload, type JobType, type SignedJob } from "./protocol";
import { MAX_POLL_WAIT_SEC, POLL_INTERVAL_MS, POLL_MAX_INTERVAL_MS, REDELIVERY_LEASE_MS } from "./policy";

/**
 * The signed job queue (ARCHITECTURE-HOSTED §3 "Job authenticity").
 *
 * - enqueueJob signs the canonical envelope ONCE and stores the signature with the exact envelope fields
 *   (id, tenant, connector, type, payload, notBefore, expiresAt), so every (re-)delivery is byte-identical.
 * - claimJobs hands out due jobs with UPDATE … FOR UPDATE SKIP LOCKED: two web instances (or two polls of
 *   one connector) never receive the same job at the same time. A delivered job without a result is
 *   re-delivered after REDELIVERY_LEASE_MS — the connector de-duplicates by job id.
 * - A retry is always a NEW job id: the connector stores one result per id and never re-executes it.
 */

export interface EnqueueInput<T extends JobType> {
  tenantId: string;
  connectorId: string;
  type: T;
  payload: JobPayload<T>;
  notBefore?: Date;
  expiresAt: Date;
  deploymentId?: string | null;
  changeRequestId?: string | null;
  /** Job generation (0 = first try); retries carry the previous value + 1 */
  attempts?: number;
  /** Idempotency key: the failed job this one retries (unique — a retry is created at most once) */
  retryOfJobId?: string | null;
}

export interface EnqueuedJob {
  id: string;
  type: JobType;
  notBefore: Date;
  expiresAt: Date;
}

export function newJobId(): string {
  return `job_${randomBytes(15).toString("base64url")}`; // 24 chars, [A-Za-z0-9_-]
}

/** Build + sign + store one job. Runs inside the caller's bank-scoped transaction. */
export async function enqueueJob<T extends JobType>(tx: Tx, input: EnqueueInput<T>, now = new Date()): Promise<EnqueuedJob> {
  // Validate exactly what the connector will validate: a job PatchGate signs is always well-formed.
  const payload = jobPayloadSchemas[input.type].parse(input.payload) as Prisma.InputJsonValue;
  const notBefore = new Date(Math.floor((input.notBefore ?? now).getTime()));
  // Connectors refuse jobs that live longer than MAX_JOB_LIFETIME_MS (protocol): never sign one.
  const expiresAt = new Date(Math.min(Math.floor(input.expiresAt.getTime()), notBefore.getTime() + MAX_JOB_LIFETIME_MS));
  if (expiresAt <= notBefore) throw new Error(`job ${input.type} would expire before it may start`);
  const id = newJobId();
  const envelope: JobEnvelope = {
    v: 1,
    id,
    tenantId: input.tenantId,
    connectorId: input.connectorId,
    type: input.type,
    payload,
    notBefore: notBefore.toISOString(),
    expiresAt: expiresAt.toISOString(),
  };
  // Signed by the bank's key (file key in dev/lab, remote signer sidecar in production: an internal HTTP
  // call). Callers must not hold long-lived locks here — the audit chain lock in particular is only taken
  // at the END of the producers' transactions (AuditBuffer), never before a signature.
  const { signature } = await signJobEnvelope(envelope);
  await tx.connectorJob.create({
    data: {
      id,
      tenantId: input.tenantId,
      connectorId: input.connectorId,
      type: input.type,
      payload,
      signature,
      notBefore,
      expiresAt,
      attempts: input.attempts ?? 0,
      deploymentId: input.deploymentId ?? null,
      changeRequestId: input.changeRequestId ?? null,
      retryOfJobId: input.retryOfJobId ?? null,
    },
  });
  return { id, type: input.type, notBefore, expiresAt };
}

interface ClaimedRow {
  id: string;
  tenantId: string;
  connectorId: string;
  type: string;
  payload: unknown;
  signature: string;
  notBefore: Date;
  expiresAt: Date;
}

/** Reassemble the signed job exactly as it was signed (no extra fields: they would break the signature). */
export function toSignedJob(row: ClaimedRow): SignedJob {
  return {
    v: 1,
    id: row.id,
    tenantId: row.tenantId,
    connectorId: row.connectorId,
    type: row.type as JobType,
    payload: row.payload,
    notBefore: row.notBefore.toISOString(),
    expiresAt: row.expiresAt.toISOString(),
    signature: row.signature,
  };
}

/** Atomically lease up to MAX_JOBS_PER_POLL due jobs of one connector. */
export async function claimJobs(tenantId: string, connectorId: string, now = new Date()): Promise<SignedJob[]> {
  const leaseCutoff = new Date(now.getTime() - REDELIVERY_LEASE_MS);
  const rows = await withTenant(tenantId, (tx) =>
    // MATERIALIZED CTE: the SKIP LOCKED pick runs exactly once. As a joined sub-select the planner may
    // re-scan it (nested loop), and every re-scan skips other rows — one poll could lease > the limit.
    tx.$queryRaw<ClaimedRow[]>`
      WITH picked AS MATERIALIZED (
        SELECT "id" FROM "ConnectorJob"
         WHERE "tenantId" = ${tenantId} AND "connectorId" = ${connectorId}
           AND "expiresAt" > ${now} AND "notBefore" <= ${now}
           AND ("status" = 'QUEUED' OR ("status" = 'DELIVERED' AND "deliveredAt" < ${leaseCutoff}))
         ORDER BY "notBefore" ASC, "createdAt" ASC
         LIMIT ${MAX_JOBS_PER_POLL}
         FOR UPDATE SKIP LOCKED)
      UPDATE "ConnectorJob" AS j
         SET "status" = 'DELIVERED', "deliveredAt" = ${now}
        FROM picked
       WHERE j."id" = picked."id"
   RETURNING j."id", j."tenantId", j."connectorId", j."type"::text AS "type", j."payload", j."signature", j."notBefore", j."expiresAt"`,
  );
  rows.sort((a, b) => a.notBefore.getTime() - b.notBefore.getTime());
  return rows.map(toSignedJob);
}

const sleep = (ms: number, signal?: AbortSignal) =>
  new Promise<void>((resolve) => {
    if (signal?.aborted) return resolve();
    const t = setTimeout(resolve, ms);
    signal?.addEventListener("abort", () => {
      clearTimeout(t);
      resolve();
    }, { once: true });
  });

/**
 * Long poll for up to `waitSec` (≤ 25 s). The queue is checked after POLL_INTERVAL_MS, then the interval
 * grows to POLL_MAX_INTERVAL_MS: an idle connector costs ≈ 13 queries per poll instead of 25, and new
 * work still reaches it within a few seconds.
 */
export async function pollJobs(tenantId: string, connectorId: string, waitSec: number, signal?: AbortSignal): Promise<SignedJob[]> {
  const wait = Math.max(0, Math.min(MAX_POLL_WAIT_SEC, Math.trunc(waitSec)));
  const deadline = Date.now() + wait * 1000;
  let interval = POLL_INTERVAL_MS;
  for (;;) {
    const jobs = await claimJobs(tenantId, connectorId);
    const left = deadline - Date.now();
    if (jobs.length > 0 || signal?.aborted || left <= 0) return jobs;
    await sleep(Math.min(interval, left), signal);
    interval = Math.min(POLL_MAX_INTERVAL_MS, interval * 2);
  }
}

export interface ExpiredJob {
  id: string;
  tenantId: string;
  connectorId: string;
  type: JobType;
  deploymentId: string | null;
  delivered: boolean;
}

/** Mark jobs past expiresAt (never answered) EXPIRED. Returns them so callers can react (deployments). */
export async function expireJobs(now = new Date()): Promise<ExpiredJob[]> {
  const rows = await withPlatform((tx) =>
    tx.$queryRaw<{ id: string; tenantId: string; connectorId: string; type: string; deploymentId: string | null; deliveredAt: Date | null }[]>`
      UPDATE "ConnectorJob" SET "status" = 'EXPIRED', "completedAt" = ${now}, "processedAt" = ${now},
             "error" = 'expired before a result arrived'
       WHERE "status" IN ('QUEUED', 'DELIVERED') AND "expiresAt" <= ${now}
   RETURNING "id", "tenantId", "connectorId", "type"::text AS "type", "deploymentId", "deliveredAt"`,
  );
  if (rows.length > 0) log.info("connector.jobs.expired", { count: rows.length });
  return rows.map((r) => ({ id: r.id, tenantId: r.tenantId, connectorId: r.connectorId, type: r.type as JobType, deploymentId: r.deploymentId, delivered: r.deliveredAt !== null }));
}

/** Cancel not-yet-delivered jobs (ring stop, revoke). Delivered ones keep running on the connector. */
export async function cancelQueuedJobs(tx: Tx, where: Prisma.ConnectorJobWhereInput, reason: string, now = new Date()): Promise<number> {
  const r = await tx.connectorJob.updateMany({ where: { ...where, status: "QUEUED" }, data: { status: "CANCELLED", error: reason, completedAt: now, processedAt: now } });
  return r.count;
}

/** Finished jobs are kept at least this long (results, audit context, troubleshooting). */
export const JOB_RETENTION_MS = 30 * 24 * 60 * 60_000;
const PURGE_BATCH = 5_000;
const PURGE_MAX_BATCHES = 20;

/**
 * Retention: delete finished, applied jobs older than JOB_RETENTION_MS. Never deleted: jobs of deployments
 * that are not finished, and the newest CACHE_PACKAGE job per (connector, package) — the site cache state
 * and package entitlement are derived from it. Bounded per call (batches); the next tick continues.
 */
export async function purgeFinishedJobs(now = new Date()): Promise<number> {
  const cutoff = new Date(now.getTime() - JOB_RETENTION_MS);
  let total = 0;
  for (let i = 0; i < PURGE_MAX_BATCHES; i++) {
    const n = await withPlatform((tx) =>
      tx.$executeRaw`
        DELETE FROM "ConnectorJob" WHERE "id" IN (
          SELECT c."id" FROM "ConnectorJob" c
           WHERE c."processedAt" IS NOT NULL AND c."completedAt" < ${cutoff}
             AND c."status" IN ('SUCCEEDED', 'FAILED', 'EXPIRED', 'CANCELLED')
             AND (c."deploymentId" IS NULL OR NOT EXISTS (
                   SELECT 1 FROM "Deployment" d WHERE d."id" = c."deploymentId" AND d."status" IN ('QUEUED', 'SENDING', 'SENT')))
             AND (c."type" <> 'CACHE_PACKAGE' OR EXISTS (
                   SELECT 1 FROM "ConnectorJob" n
                    WHERE n."type" = 'CACHE_PACKAGE' AND n."connectorId" = c."connectorId" AND n."createdAt" > c."createdAt"
                      AND (n."payload" -> 'package' ->> 'sha256') = (c."payload" -> 'package' ->> 'sha256')))
           LIMIT ${PURGE_BATCH})`,
    );
    total += n;
    if (n < PURGE_BATCH) break;
  }
  if (total > 0) log.info("connector.jobs.purged", { count: total });
  return total;
}
