import "server-only";
import { prisma } from "@/lib/db";
import { log } from "@/lib/log";
import type { WorkerStepOps } from "./types";

/**
 * Worker step timings (WorkerStepRun): the tick route records one row per step after every run, so any web
 * instance can export them (/api/metrics) and /operations can show "last run / duration / last success".
 * The latest summary is also kept in-process for the instance that ran it.
 */

export interface StepRun {
  step: string;
  durationMs: number;
  ok: boolean;
  status: string;
  at: Date;
}

/** Name of the pseudo-step covering a whole tick. */
export const TICK_STEP = "tick";
const STATUS_MAX = 300;
const STEP_RE = /^[A-Za-z0-9_.-]{1,64}$/;

let lastLocal: StepRun[] = [];

/** Last runs recorded by THIS process (diagnostics). */
export function lastLocalStepRuns(): readonly StepRun[] {
  return lastLocal;
}

/** Persist one tick's step runs (single statement). Never throws: monitoring must not fail the tick. */
export async function recordStepRuns(runs: readonly StepRun[]): Promise<void> {
  const valid = runs.filter((r) => STEP_RE.test(r.step));
  lastLocal = [...valid];
  if (valid.length === 0) return;
  const steps = valid.map((r) => r.step);
  const at = valid.map((r) => r.at);
  const dur = valid.map((r) => Math.max(0, Math.round(r.durationMs)));
  const ok = valid.map((r) => r.ok);
  const status = valid.map((r) => r.status.slice(0, STATUS_MAX));
  try {
    await prisma.$executeRaw`
      INSERT INTO "WorkerStepRun" AS w ("step", "lastRunAt", "lastDurationMs", "lastOk", "lastStatus", "lastSuccessAt", "lastFailureAt", "runs", "failures", "totalDurationMs")
      SELECT s.step, s.at, s.dur, s.ok, s.status,
             CASE WHEN s.ok THEN s.at END, CASE WHEN s.ok THEN NULL ELSE s.at END,
             1, CASE WHEN s.ok THEN 0 ELSE 1 END, s.dur
        FROM unnest(${steps}::text[], ${at}::timestamp(3)[], ${dur}::int[], ${ok}::boolean[], ${status}::text[]) AS s(step, at, dur, ok, status)
      ON CONFLICT ("step") DO UPDATE SET
        "lastRunAt" = EXCLUDED."lastRunAt",
        "lastDurationMs" = EXCLUDED."lastDurationMs",
        "lastOk" = EXCLUDED."lastOk",
        "lastStatus" = EXCLUDED."lastStatus",
        "lastSuccessAt" = COALESCE(EXCLUDED."lastSuccessAt", w."lastSuccessAt"),
        "lastFailureAt" = COALESCE(EXCLUDED."lastFailureAt", w."lastFailureAt"),
        "runs" = w."runs" + 1,
        "failures" = w."failures" + EXCLUDED."failures",
        "totalDurationMs" = w."totalDurationMs" + EXCLUDED."totalDurationMs"`;
  } catch (err: unknown) {
    log.warn("metrics.worker_steps.record_failed", { steps: steps.length, err });
  }
}

const FAILED_PREFIX = "FAILED: ";

export interface StepTimer {
  /** Pass as TickDeps.onStep. */
  onStep: (name: string, status: string, durationMs: number) => void;
  /** After the tick: persist every step + the whole tick. `ran` = false when the lease was not obtained. */
  finish: (ran: boolean, tickOk: boolean) => Promise<void>;
}

/** Collects step timings during one tick (used by the tick route). */
export function stepTimer(now: () => Date = () => new Date()): StepTimer {
  const started = now();
  const runs: StepRun[] = [];
  return {
    onStep: (name, status, durationMs) => {
      runs.push({ step: name, status, durationMs, ok: !status.startsWith(FAILED_PREFIX), at: now() });
    },
    finish: async (ran, tickOk) => {
      if (!ran) return; // another instance holds the tick lease: nothing ran here
      const end = now();
      const tick: StepRun = { step: TICK_STEP, durationMs: end.getTime() - started.getTime(), ok: tickOk, status: tickOk ? "ok" : "partial", at: end };
      await recordStepRuns([...runs, tick]);
    },
  };
}

export async function readStepRuns(): Promise<WorkerStepOps[]> {
  const rows = await prisma.workerStepRun.findMany({ orderBy: { step: "asc" } });
  return rows.map((r) => ({
    step: r.step,
    lastRunAt: r.lastRunAt,
    lastDurationMs: r.lastDurationMs,
    lastOk: r.lastOk,
    lastStatus: r.lastStatus,
    lastSuccessAt: r.lastSuccessAt,
    lastFailureAt: r.lastFailureAt,
    runs: Number(r.runs),
    failures: Number(r.failures),
    totalDurationMs: Number(r.totalDurationMs),
  }));
}
