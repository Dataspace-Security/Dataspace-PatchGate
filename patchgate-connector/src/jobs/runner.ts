import { z } from "zod";
import type { Journal } from "../journal.ts";
import { PatchGateError, type PatchGateClient } from "../pg-client.ts";
import { verifyJob, type JobResult, type JobType, type SignedJob } from "../protocol.ts";
import { AbortedError, backoffDelay, sleep } from "../util/backoff.ts";
import { errorMessage, type Logger } from "../util/log.ts";
import type { Semaphore } from "../util/semaphore.ts";
import { JobError, toJobError } from "./errors.ts";
import { executeJob, isDeployJob, isNonIdempotent, isReadOnlyJob, packagePaths, type ExecutorDeps } from "./executors.ts";
import { jsonBytes, MAX_RESULT_BYTES } from "./result-size.ts";

/**
 * Job pipeline: shape check → verifyJob (pinned key, connectorId, validity window, lifetime cap, typed
 * payload) → de-duplicate via the journal → concurrency limits → expiry re-check → execute → journal →
 * POST result (retried with backoff + jitter while the failure is retryable; unacknowledged results of
 * non-read-only jobs survive restarts).
 */

const rawJobSchema = z
  .object({
    v: z.number(),
    id: z.string().regex(/^[A-Za-z0-9_-]{1,64}$/),
    tenantId: z.string(),
    connectorId: z.string(),
    type: z.string().max(64),
    payload: z.unknown(),
    notBefore: z.string(),
    expiresAt: z.string(),
    signature: z.string().max(200),
  })
  .loose(); // keep every field: the signature covers the envelope exactly as PatchGate signed it

export interface JobRunnerOptions {
  pg: PatchGateClient;
  journal: Journal;
  deps: Omit<ExecutorDeps, "signal">;
  connectorId: string;
  jobSigningPublicKey: string;
  deploySem: Semaphore;
  otherSem: Semaphore;
  log: Logger;
  now?: () => number;
  /** Retry delays for result posting. */
  postBackoff?: { baseMs: number; maxMs: number };
  /** Cap on one serialised result body (default MAX_RESULT_BYTES). */
  maxResultBytes?: number;
}

/** Rejections where the job id itself is not trustworthy → never answered. */
const UNTRUSTED_REJECTIONS = new Set(["bad job signature", "unsupported job version", "job is for another connector"]);

const failure = (error: string, extra: { outcomeUnknown?: boolean; retryable?: boolean } = {}): JobResult => ({
  ok: false,
  error: error.slice(0, 2000),
  retryable: extra.retryable ?? false,
  ...(extra.outcomeUnknown ? { outcomeUnknown: true } : {}),
});

export class JobRunner {
  private readonly inflight = new Set<string>();
  private readonly tasks = new Set<Promise<void>>();
  /** Fires when we stop accepting: queued (not started) jobs are abandoned, PatchGate re-delivers them. */
  private readonly stopQueue = new AbortController();
  /** Fires after the grace period: running executors and result retries are aborted. */
  private readonly hardStop = new AbortController();
  readonly stats = { received: 0, executed: 0, rejected: 0, duplicates: 0, posted: 0, expiredBeforeStart: 0, postFailedPermanently: 0 };

  constructor(private readonly o: JobRunnerOptions) {}

  private now(): number {
    return (this.o.now ?? Date.now)();
  }

  /** Jobs queued or running (used to pause polling when saturated). */
  get load(): number {
    return this.inflight.size;
  }

  get accepting(): boolean {
    return !this.stopQueue.signal.aborted;
  }

  /** Re-post results recorded before a restart but never acknowledged. */
  resendUnposted(): number {
    const pending = this.o.journal.unposted();
    for (const s of pending) {
      if (s.result) this.trackInflight(s.jobId, this.postWithRetry(s.jobId, s.result));
    }
    if (pending.length) this.o.log.info("re-sending unacknowledged results", { count: pending.length });
    return pending.length;
  }

  /** Accept one job from GET /jobs. Never throws; returns once the job is scheduled (not finished). */
  async submit(raw: unknown): Promise<void> {
    this.stats.received++;
    const log = this.o.log;
    if (!this.accepting) return;
    const shape = rawJobSchema.safeParse(raw);
    if (!shape.success) {
      this.stats.rejected++;
      log.error("malformed job dropped", { issue: shape.error.issues[0]?.message });
      return;
    }
    const job = shape.data as unknown as SignedJob;
    const jlog = log.child({ jobId: job.id, jobType: String(job.type).slice(0, 32) });

    if (this.inflight.has(job.id)) {
      this.stats.duplicates++;
      return; // already queued/running/posting
    }

    const prior = this.o.journal.get(job.id);
    if (prior?.result) {
      // Re-delivered while our result is still unacknowledged: re-send it, never re-execute.
      this.stats.duplicates++;
      jlog.info("re-delivered job: re-sending stored result");
      this.trackInflight(job.id, this.postWithRetry(job.id, prior.result));
      return;
    }

    const check = verifyJob(job, this.o.jobSigningPublicKey, this.o.connectorId, this.now());
    if (!check.ok) {
      this.stats.rejected++;
      if (UNTRUSTED_REJECTIONS.has(check.reason)) {
        jlog.error("job REJECTED (not executed, not answered)", { reason: check.reason, security: true });
        return;
      }
      if (check.reason === "job not yet valid") {
        jlog.warn("job not yet valid; ignored until re-delivered", { notBefore: job.notBefore });
        return;
      }
      // Authentic (signed for us) but unusable (expired, lifetime too long, bad payload, unknown type):
      // answer with a permanent failure.
      jlog.warn("job rejected", { reason: check.reason, security: check.reason === "job lifetime too long" });
      const type = /^[A-Z_]{1,32}$/.test(job.type) ? job.type : "UNKNOWN";
      const result = await this.o.journal.markDone(job.id, type, failure(`rejected by connector: ${check.reason}`));
      this.trackInflight(job.id, this.postWithRetry(job.id, result));
      return;
    }

    if (prior?.doneAt) {
      // Executed before and the result was acknowledged (body no longer held) or was a read-only body
      // that is never journaled.
      if (!isReadOnlyJob(check.type)) {
        this.stats.duplicates++;
        jlog.warn("re-delivered job already executed; not executed again", { postOutcome: prior.postOutcome });
        const result = failure(
          `already executed by this connector (ok=${String(prior.summary?.ok ?? false)}, result ${prior.postOutcome ?? "recorded"}); not executed again - confirm via inventory`,
          { outcomeUnknown: isDeployJob(check.type) },
        );
        this.trackInflight(job.id, this.postWithRetry(job.id, result));
        return;
      }
      jlog.info("re-delivered read-only job: running it again (safe)");
    } else if (prior?.startedAt && isNonIdempotent(check.type)) {
      // We crashed/stopped while this install was running: re-running could start a second installer.
      jlog.warn("job was interrupted mid-execution; reporting outcome unknown");
      const result = await this.o.journal.markDone(
        job.id,
        check.type,
        failure("interrupted: the connector stopped while this job was running; outcome unknown - confirm via inventory", { outcomeUnknown: true }),
        { expiresAt: job.expiresAt },
      );
      this.trackInflight(job.id, this.postWithRetry(job.id, result));
      return;
    }

    await this.pinPackages(check.type, check.payload, job.expiresAt, jlog);
    this.trackInflight(job.id, this.run(job.id, check.type, check.payload, job.expiresAt, jlog));
  }

  /** Protect the packages this job needs from cache eviction until the job expires. */
  private async pinPackages(type: JobType, payload: unknown, expiresAt: string, jlog: Logger): Promise<void> {
    const paths = packagePaths(type, payload);
    if (paths.length === 0) return;
    try {
      await this.o.deps.index.pin(paths, Date.parse(expiresAt));
    } catch (err) {
      jlog.warn("could not record cache pins (eviction may remove the package early)", { error: errorMessage(err) });
    }
  }

  private async run(jobId: string, type: JobType, payload: unknown, expiresAt: string, jlog: Logger): Promise<void> {
    const sem = isDeployJob(type) ? this.o.deploySem : this.o.otherSem;
    try {
      await sem.acquire(this.stopQueue.signal);
    } catch {
      jlog.info("queued job abandoned on shutdown (PatchGate will re-deliver)");
      return;
    }
    const keepBody = !isReadOnlyJob(type);
    let result: JobResult;
    const started = Date.now();
    try {
      // The job may have waited for a slot past its window: never start it late.
      if (this.now() >= Date.parse(expiresAt)) {
        this.stats.expiredBeforeStart++;
        jlog.warn("job expired while queued; not started", { expiresAt });
        result = await this.o.journal.markDone(jobId, type, failure("expired before start: the job's validity window closed while it waited for a free slot"), {
          expiresAt,
        });
      } else {
        await this.o.journal.markStarted(jobId, type, expiresAt);
        jlog.info("job started");
        try {
          const out = await executeJob(type, payload, { ...this.o.deps, signal: this.hardStop.signal });
          result = this.capResult(type, { ok: true, result: out }, jlog);
        } catch (err) {
          if (this.hardStop.signal.aborted) {
            jlog.warn("job aborted by shutdown; will be re-delivered", { error: errorMessage(err) });
            return;
          }
          const je: JobError = toJobError(err);
          result = failure(je.message, { retryable: je.retryable && !je.outcomeUnknown, outcomeUnknown: je.outcomeUnknown });
        }
        result = await this.o.journal.markDone(jobId, type, result, { keepBody, expiresAt });
        this.stats.executed++;
        jlog.info("job finished", {
          ok: result.ok,
          retryable: result.ok ? undefined : result.retryable,
          outcomeUnknown: result.ok ? undefined : result.outcomeUnknown,
          error: result.ok ? undefined : result.error,
          durationMs: Date.now() - started,
        });
      }
    } finally {
      sem.release();
    }
    await this.postWithRetry(jobId, result);
  }

  /** Last line of defence against a result PatchGate would refuse with 413. */
  private capResult(type: JobType, result: JobResult, jlog: Logger): JobResult {
    const max = this.o.maxResultBytes ?? MAX_RESULT_BYTES;
    const bytes = jsonBytes(result);
    if (bytes <= max) return result;
    jlog.error("job result too large; reporting a permanent failure instead", { bytes, maxBytes: max });
    return failure(`result too large (${bytes} bytes > ${max}); split the ${type} job`, { outcomeUnknown: isDeployJob(type) });
  }

  private async postWithRetry(jobId: string, first: JobResult): Promise<void> {
    const backoff = this.o.postBackoff ?? { baseMs: 1000, maxMs: 300_000 };
    const signal = this.hardStop.signal;
    let result = first;
    for (let attempt = 0; ; attempt++) {
      try {
        const outcome = await this.o.pg.postResult(jobId, result, signal);
        await this.o.journal.markPosted(jobId, result === first ? outcome : `${outcome}-stub`.slice(0, 32));
        this.stats.posted++;
        const level = outcome === "accepted" || outcome === "duplicate" ? "info" : "warn";
        this.o.log[level]("job result delivered", { jobId, outcome });
        return;
      } catch (err) {
        if (signal.aborted || err instanceof AbortedError) return; // stays in the journal; re-sent on next start
        if (err instanceof PatchGateError && !err.retryable) {
          if (err.status === 413 && result === first) {
            // PatchGate refuses the body: deliver a small permanent failure instead, never loop.
            this.o.log.error("PatchGate refused the job result as too large (413); posting a permanent-failure stub", { jobId, bytes: jsonBytes(first) });
            result = failure("result too large: PatchGate refused the result body (HTTP 413)", { outcomeUnknown: !first.ok && first.outcomeUnknown === true });
            attempt = -1;
            continue;
          }
          this.stats.postFailedPermanently++;
          this.o.log.error("posting job result failed permanently; not retrying (re-sent on next start if journaled)", { jobId, status: err.status, error: errorMessage(err) });
          return;
        }
        const retryAfter = err instanceof PatchGateError ? err.retryAfterMs : undefined;
        const delay = Math.max(retryAfter ?? 0, backoffDelay(attempt, backoff));
        this.o.log.warn("posting job result failed; retrying", { jobId, attempt, delayMs: delay, error: errorMessage(err) });
        try {
          await sleep(delay, signal);
        } catch {
          return;
        }
      }
    }
  }

  private trackInflight(jobId: string, p: Promise<void>): void {
    this.inflight.add(jobId);
    this.track(p.finally(() => this.inflight.delete(jobId)));
  }

  private track(p: Promise<void>): void {
    const t = p.catch((err: unknown) => this.o.log.error("job task crashed", { err }));
    this.tasks.add(t);
    void t.finally(() => this.tasks.delete(t));
  }

  /** Wait until every scheduled task finished (tests / shutdown). */
  async idle(): Promise<void> {
    while (this.tasks.size > 0) await Promise.all([...this.tasks]);
  }

  /** Graceful shutdown: drop queued jobs, give running ones `graceMs`, then abort the rest. */
  async shutdown(graceMs: number): Promise<void> {
    this.stopQueue.abort();
    const all = Promise.all([...this.tasks]);
    let timer: NodeJS.Timeout | undefined;
    const timedOut = await Promise.race([
      all.then(() => false),
      new Promise<boolean>((resolve) => {
        timer = setTimeout(() => resolve(true), graceMs);
      }),
    ]);
    clearTimeout(timer);
    if (timedOut) this.o.log.warn("shutdown grace expired; aborting running jobs", { running: this.inflight.size });
    this.hardStop.abort();
    await Promise.race([all, new Promise((r) => setTimeout(r, 5000))]);
  }
}
