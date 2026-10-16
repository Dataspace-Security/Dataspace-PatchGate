/**
 * Process-local TTL cache with in-flight de-duplication: concurrent callers share ONE computation, and the
 * value is reused until it is `ttlMs` old. A failed computation is not cached (the next call retries), but
 * failures can be cached for `errorTtlMs` to protect a struggling dependency.
 */

interface Entry<T> {
  at: number;
  value?: T;
  error?: unknown;
}

export interface CacheOptions {
  ttlMs: number;
  /** Cache failures this long (default 0 = retry immediately). */
  errorTtlMs?: number;
  now?: () => number;
}

export interface Cached<T> {
  get(): Promise<T>;
  /** Drop the cached value (tests / forced refresh). */
  reset(): void;
}

export function cached<T>(compute: () => Promise<T>, opts: CacheOptions): Cached<T> {
  const now = opts.now ?? Date.now;
  let entry: Entry<T> | null = null;
  let inFlight: Promise<T> | null = null;

  const get = (): Promise<T> => {
    const t = now();
    if (entry) {
      if (entry.error === undefined && t - entry.at < opts.ttlMs) return Promise.resolve(entry.value as T);
      if (entry.error !== undefined && t - entry.at < (opts.errorTtlMs ?? 0)) return Promise.reject(entry.error);
    }
    if (inFlight) return inFlight;
    inFlight = (async () => {
      try {
        const value = await compute();
        entry = { at: now(), value };
        return value;
      } catch (error: unknown) {
        entry = opts.errorTtlMs ? { at: now(), error } : null;
        throw error;
      } finally {
        inFlight = null;
      }
    })();
    return inFlight;
  };

  return {
    get,
    reset: () => {
      entry = null;
    },
  };
}
