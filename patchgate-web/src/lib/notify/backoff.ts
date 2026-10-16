/** Delivery retry policy (pure). */

export const MAX_ATTEMPTS = 8;
const BASE_MS = 60_000;
const CAP_MS = 6 * 60 * 60_000;

/** Delay before the next attempt after `attempts` failed ones: 1, 2, 4 … min, capped at 6 h. */
export function backoffMs(attempts: number): number {
  const n = Math.max(1, Math.floor(attempts));
  return Math.min(CAP_MS, BASE_MS * 2 ** Math.min(n - 1, 30));
}

export type FailureVerdict = { status: "PENDING"; nextAttemptAt: Date } | { status: "DEAD" };

/** After a failed attempt: retry later, or dead-letter (permanent error / attempts exhausted). */
export function afterFailure(attempts: number, permanent: boolean, now: Date): FailureVerdict {
  if (permanent || attempts >= MAX_ATTEMPTS) return { status: "DEAD" };
  return { status: "PENDING", nextAttemptAt: new Date(now.getTime() + backoffMs(attempts)) };
}
