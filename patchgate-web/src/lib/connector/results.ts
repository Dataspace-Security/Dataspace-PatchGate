import "server-only";
import type { Prisma } from "@prisma/client";
import { withPlatform, withTenant } from "@/lib/tenancy";
import { withLease } from "@/lib/deploy/lease";
import { pumpConnectorSafe } from "@/lib/deploy/connector-deploy";
import { log } from "@/lib/log";
import type { AuthedConnector } from "./auth";
import { ConnectorApiError } from "./errors";
import { jobResultSchema, resultSchemas, type JobResult, type JobType } from "./protocol";
import { applyJobOutcome, type StoredJob } from "./handlers";
import { isInstallJob } from "./policy";

/**
 * Job results (POST /api/connector/v1/jobs/{id}/result).
 *
 * acceptResult is fast and idempotent: the FIRST result for a job wins (later posts → 409, which the
 * connector treats as delivered); an unknown job → 404; an invalid result → 422 (stored as a failure).
 * The result is stored raw and applied asynchronously by processJobResult (right after the response,
 * and again by the worker tick for anything left over), so a 200-agent COLLECT page never holds the
 * connector's request open.
 */

const MAX_PROCESS_ATTEMPTS = 3;
const PROCESS_LEASE_MS = 10 * 60_000;
const JOB_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;

export interface AcceptedResult {
  jobId: string;
  status: "SUCCEEDED" | "FAILED";
}

interface LockedJob {
  id: string;
  type: string;
  status: string;
  hasResult: boolean;
}

export async function acceptResult(connector: AuthedConnector, jobId: string, body: unknown, now = new Date()): Promise<AcceptedResult> {
  if (!JOB_ID_RE.test(jobId)) throw new ConnectorApiError(404, "unknown job");
  const parsed = jobResultSchema.safeParse(body);
  if (!parsed.success) throw new ConnectorApiError(400, `invalid result envelope: ${parsed.error.issues[0]?.message ?? "malformed"}`);
  const res: JobResult = parsed.data;

  const stored = await withTenant(connector.tenantId, async (tx) => {
    const [job] = await tx.$queryRaw<LockedJob[]>`
      SELECT "id", "type"::text AS "type", "status"::text AS "status", ("result" IS NOT NULL OR "status" IN ('SUCCEEDED', 'FAILED')) AS "hasResult"
        FROM "ConnectorJob"
       WHERE "id" = ${jobId} AND "connectorId" = ${connector.id} AND "tenantId" = ${connector.tenantId}
         FOR UPDATE`;
    if (!job) throw new ConnectorApiError(404, "unknown job");
    if (job.hasResult) throw new ConnectorApiError(409, "a result for this job was already accepted");

    const type = job.type as JobType;
    let status: "SUCCEEDED" | "FAILED";
    let result: Prisma.InputJsonValue;
    let error: string | null = null;
    let invalid: string | null = null;
    if (res.ok) {
      const checked = resultSchemas[type].safeParse(res.result);
      if (checked.success) {
        status = "SUCCEEDED";
        result = { ok: true, result: checked.data as Prisma.InputJsonValue };
      } else {
        invalid = `invalid ${type} result: ${checked.error.issues[0]?.path.join(".") ?? ""} ${checked.error.issues[0]?.message ?? ""}`.trim();
        status = "FAILED";
        error = invalid.slice(0, 2000);
        result = { ok: false, error, retryable: false };
      }
    } else {
      status = "FAILED";
      error = res.error.slice(0, 2000);
      // outcomeUnknown must survive storage: it decides "confirm via inventory" vs "fail / retry".
      result = { ok: false, error, retryable: res.retryable, ...(res.outcomeUnknown ? { outcomeUnknown: true } : {}) };
    }
    // A late result for an EXPIRED / CANCELLED job is still recorded and applied: the work happened.
    await tx.connectorJob.update({
      where: { id: jobId },
      data: { status, result, error, completedAt: now, processedAt: null, processAttempts: 0 },
    });
    return { status, invalid, type };
  });
  if (stored.invalid) {
    // Stored as a permanent failure (committed above); the connector must not retry it.
    log.warn("connector.result.invalid", { jobId, tenantId: connector.tenantId, connectorId: connector.id, type: stored.type, problem: stored.invalid });
    throw new ConnectorApiError(422, stored.invalid);
  }
  return { jobId, status: stored.status };
}

/** Stored result envelope (as written by acceptResult). */
function storedResult(v: Prisma.JsonValue | null): JobResult | null {
  const r = jobResultSchema.safeParse(v);
  return r.success ? r.data : null;
}

/** Types whose raw result can be large: keep only a summary once applied. */
const COMPACT: Partial<Record<JobType, (r: unknown) => Prisma.InputJsonValue>> = {
  SYNC_AGENTS: (r) => ({ agents: (r as { agents?: unknown[] }).agents?.length ?? 0 }),
  COLLECT: (r) => ({ agents: (r as { agents?: unknown[] }).agents?.length ?? 0 }),
  WU_SCAN: (r) => ({ agents: (r as { agents?: unknown[] }).agents?.length ?? 0 }),
};

/**
 * Apply one stored result (idempotent; under a cluster-wide lease so two instances never apply the same
 * result twice). A handler failure is retried on later ticks, at most MAX_PROCESS_ATTEMPTS times.
 */
export async function processJobResult(tenantId: string, jobId: string, now = new Date()): Promise<"applied" | "skipped" | "failed"> {
  const outcome = await withLease(`connector-result:${jobId}`, PROCESS_LEASE_MS, async () => {
    const job = await withTenant(tenantId, (tx) => tx.connectorJob.findFirst({ where: { id: jobId, tenantId } }));
    if (!job || job.processedAt || !job.completedAt || (job.status !== "SUCCEEDED" && job.status !== "FAILED")) return "skipped" as const;
    const res = storedResult(job.result);
    const stored: StoredJob = {
      id: job.id,
      tenantId: job.tenantId,
      connectorId: job.connectorId,
      type: job.type as JobType,
      payload: job.payload,
      attempts: job.attempts,
      deploymentId: job.deploymentId,
      changeRequestId: job.changeRequestId,
      notBefore: job.notBefore,
      expiresAt: job.expiresAt,
      deliveredAt: job.deliveredAt,
    };
    try {
      await applyJobOutcome(stored, res ?? { ok: false, error: job.error ?? "result missing", retryable: false }, now);
      const compact = res?.ok ? COMPACT[stored.type] : undefined;
      await withTenant(tenantId, (tx) =>
        tx.connectorJob.update({
          where: { id: jobId },
          data: {
            processedAt: new Date(),
            processAttempts: { increment: 1 },
            ...(compact && res?.ok ? { result: { ok: true, result: compact(res.result), compacted: true } } : {}),
          },
        }),
      );
      // Results free install slots / complete site caches: release the next installs right away.
      if (isInstallJob(stored.type) || stored.type === "CACHE_PACKAGE") await pumpConnectorSafe(stored.tenantId, stored.connectorId);
      return "applied" as const;
    } catch (err: unknown) {
      const attempts = job.processAttempts + 1;
      log.error("connector.result.apply_failed", { jobId, tenantId: stored.tenantId, connectorId: stored.connectorId, type: stored.type, attempts, err });
      await withTenant(tenantId, (tx) =>
        tx.connectorJob.update({
          where: { id: jobId },
          data: {
            processAttempts: attempts,
            ...(attempts >= MAX_PROCESS_ATTEMPTS
              ? { processedAt: new Date(), error: `result could not be applied: ${err instanceof Error ? err.message : "error"}`.slice(0, 2000) }
              : {}),
          },
        }),
      );
      return "failed" as const;
    }
  });
  return outcome ?? "skipped";
}

/** Results that free install slots / unblock deployments are applied first. */
const PRIORITY_TYPES = ["DEPLOY_WINDOWS", "DEPLOY_PACKAGE", "WU_INSTALL", "CACHE_PACKAGE"] as const satisfies readonly JobType[];
/** One tick spends at most this long applying results; the rest waits for the next tick. */
export const RESULTS_TIME_BUDGET_MS = 60_000;

/**
 * Worker step: apply accepted results that are still pending — install / cache results first (they
 * release the next installs), then inventory pages (COLLECT / SYNC / WU_SCAN: up to 200 PCs each),
 * oldest first, within a time budget so later tick steps (deploy, confirm, schedule) always run.
 */
export async function processPendingResults(limit = 200, budgetMs = RESULTS_TIME_BUDGET_MS): Promise<{ applied: number; failed: number; deferred: boolean }> {
  const started = Date.now();
  const base = { processedAt: null, completedAt: { not: null }, status: { in: ["SUCCEEDED", "FAILED"] }, processAttempts: { lt: MAX_PROCESS_ATTEMPTS } } satisfies Prisma.ConnectorJobWhereInput;
  const pick = (where: Prisma.ConnectorJobWhereInput, take: number) =>
    withPlatform((tx) => tx.connectorJob.findMany({ where: { ...base, ...where }, orderBy: { completedAt: "asc" }, take, select: { id: true, tenantId: true } }));
  const priority = await pick({ type: { in: [...PRIORITY_TYPES] } }, limit);
  const rest = priority.length < limit ? await pick({ type: { notIn: [...PRIORITY_TYPES] } }, limit - priority.length) : [];
  let applied = 0;
  let failed = 0;
  let deferred = false;
  for (const j of [...priority, ...rest]) {
    if (Date.now() - started > budgetMs) {
      deferred = true;
      break;
    }
    const r = await processJobResult(j.tenantId, j.id);
    if (r === "applied") applied++;
    else if (r === "failed") failed++;
  }
  if (deferred) log.warn("connector.results.deferred", { applied, failed, budgetMs });
  return { applied, failed, deferred };
}
