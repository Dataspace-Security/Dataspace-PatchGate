/**
 * Pure rules of the connector job pipeline (no I/O) — shared by the queue, the producers, the UI and tests.
 */
import type { JobType } from "./protocol";

/** A connector not heard from for this long is "offline": new jobs wait, the dashboard warns. */
export const OFFLINE_AFTER_MS = 10 * 60_000;

/** Delivered jobs without a result are re-delivered after this (connector restarted / lost the poll). */
export const REDELIVERY_LEASE_MS = 5 * 60_000;

/** Long poll: the connector asks for ≤ 25 s; the server checks the queue after 1 s, then every 2 s. */
export const MAX_POLL_WAIT_SEC = 25;
export const POLL_INTERVAL_MS = 1_000;
export const POLL_MAX_INTERVAL_MS = 2_000;

/** Job generations (first try + retries) before a retryable failure becomes final. */
export const MAX_JOB_ATTEMPTS = 5;

/** Jobs that start an installation on a PC — limited per connector by maxConcurrentInstalls. */
export const INSTALL_JOB_TYPES = ["DEPLOY_WINDOWS", "DEPLOY_PACKAGE", "WU_INSTALL"] as const satisfies readonly JobType[];
export type InstallJobType = (typeof INSTALL_JOB_TYPES)[number];

export function isInstallJob(t: JobType): t is InstallJobType {
  return (INSTALL_JOB_TYPES as readonly string[]).includes(t);
}

/** Request body caps (bytes). Results may carry a 200-agent COLLECT page. */
export const BODY_LIMITS = {
  enroll: 4 * 1024,
  heartbeat: 32 * 1024,
  /** Real-time Tactical guard push: <= 200 audit entries + <= 200 approval resets. */
  tacticalEvents: 1024 * 1024,
  result: 32 * 1024 * 1024,
  get: 0,
} as const;

/** Ids the connector accepts for connectors / tenants / jobs. */
export const CONNECTOR_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;

export function isOnline(lastSeenAt: Date | null | undefined, now: Date): boolean {
  return !!lastSeenAt && now.getTime() - lastSeenAt.getTime() <= OFFLINE_AFTER_MS;
}

/** Exponential backoff for retryable job failures: 1, 2, 4, 8 … min (cap 60), ±20 % jitter. */
export function retryDelayMs(attempt: number, rand: () => number = Math.random): number {
  const base = Math.min(60, 2 ** Math.max(0, attempt)) * 60_000;
  return Math.round(base * (0.8 + 0.4 * rand()));
}

/** Spread install starts so a whole site does not hit the cache / WAN in the same second. */
export const MAX_STAGGER_MS = 10 * 60_000;
/** Spread per concurrent install slot: a wave of N installs starts over about N × 6 s (≈ 10 per minute). */
export const STAGGER_PER_SLOT_MS = 6_000;

/**
 * Random start offset inside the maintenance window. The spread grows with the site's wave size
 * (maxConcurrentInstalls × 6 s), and is capped at a quarter of the remaining window and MAX_STAGGER_MS,
 * so every job still has most of the window to run.
 */
export function staggerOffsetMs(windowRemainingMs: number | null, maxConcurrentInstalls: number, rand: () => number = Math.random): number {
  const wave = Math.max(1, maxConcurrentInstalls) * STAGGER_PER_SLOT_MS;
  const window = windowRemainingMs === null ? MAX_STAGGER_MS : Math.max(0, windowRemainingMs / 4);
  return Math.floor(rand() * Math.min(MAX_STAGGER_MS, wave, window));
}

/**
 * Ring stop: more than 20 % failures once at least 10 results are in. Callers pass provisional successes
 * (install reported OK, awaiting inventory confirmation) as successes and only INSTALL failures as failures.
 */
export const RING_STOP_MIN_RESULTS = 10;
export const RING_STOP_FAILURE_RATE = 0.2;

export function ringShouldStop(succeeded: number, failed: number): boolean {
  const total = succeeded + failed;
  return total >= RING_STOP_MIN_RESULTS && failed / total > RING_STOP_FAILURE_RATE;
}

/** How many more install jobs a connector may receive now. */
export function installSlots(maxConcurrentInstalls: number, inFlight: number): number {
  return Math.max(0, maxConcurrentInstalls - inFlight);
}
