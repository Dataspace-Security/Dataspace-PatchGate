/** Account lockout rules (pure): 5 consecutive failed sign-in steps lock the account for 15 minutes. */

export const MAX_FAILED_LOGINS = 5;
export const LOCKOUT_MINUTES = 15;

export function isLocked(lockedUntil: Date | null, now: Date): boolean {
  return lockedUntil !== null && lockedUntil > now;
}

export interface FailureOutcome {
  failedLogins: number;
  lockedUntil: Date | null;
  /** True when this failure triggered the lock (audit "auth.lockout"). */
  lockedNow: boolean;
}

/**
 * Given the failure count AFTER this failure was counted, decide whether to lock.
 * Locking resets the counter so the user gets a fresh 5 attempts once the lock expires.
 */
export function failureOutcome(countAfter: number, now: Date): FailureOutcome {
  if (countAfter >= MAX_FAILED_LOGINS) {
    return { failedLogins: 0, lockedUntil: new Date(now.getTime() + LOCKOUT_MINUTES * 60_000), lockedNow: true };
  }
  return { failedLogins: countAfter, lockedUntil: null, lockedNow: false };
}
