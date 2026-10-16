/** Exponential backoff with full jitter, plus an abortable sleep. */

export interface BackoffOptions {
  baseMs: number;
  maxMs: number;
  random?: () => number;
}

/** Delay before retry number `attempt` (0-based): random in [base/2, min(max, base*2^attempt)]. */
export function backoffDelay(attempt: number, opts: BackoffOptions): number {
  const random = opts.random ?? Math.random;
  const ceiling = Math.min(opts.maxMs, opts.baseMs * 2 ** Math.min(attempt, 30));
  const floor = Math.min(ceiling, opts.baseMs / 2);
  return Math.round(floor + random() * (ceiling - floor));
}

export class AbortedError extends Error {
  constructor() {
    super("aborted");
    this.name = "AbortedError";
  }
}

/** Sleep that rejects with AbortedError when the signal fires. */
export function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new AbortedError());
      return;
    }
    const onAbort = () => {
      clearTimeout(timer);
      reject(new AbortedError());
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, Math.max(0, ms));
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}
