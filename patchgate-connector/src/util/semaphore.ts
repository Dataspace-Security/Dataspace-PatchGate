/**
 * Counting semaphore with a capacity that can change at runtime (e.g. maxConcurrentInstalls
 * delivered by the PatchGate heartbeat). Lowering the capacity never interrupts running holders;
 * it only delays new acquisitions until enough holders have released.
 */
export class Semaphore {
  private active = 0;
  private readonly waiters: Array<() => void> = [];

  constructor(private cap: number) {
    Semaphore.assertCapacity(cap);
  }

  private static assertCapacity(n: number): void {
    if (!Number.isInteger(n) || n < 1) throw new Error("semaphore capacity must be a positive integer");
  }

  get capacity(): number {
    return this.cap;
  }

  get inUse(): number {
    return this.active;
  }

  get waiting(): number {
    return this.waiters.length;
  }

  setCapacity(n: number): void {
    Semaphore.assertCapacity(n);
    this.cap = n;
    this.drain();
  }

  /** Try to take a permit without waiting. */
  tryAcquire(): boolean {
    if (this.active < this.cap && this.waiters.length === 0) {
      this.active++;
      return true;
    }
    return false;
  }

  /** Wait for a permit. If `signal` aborts while waiting, rejects and takes no permit. */
  acquire(signal?: AbortSignal): Promise<void> {
    if (signal?.aborted) return Promise.reject(new Error("aborted"));
    if (this.tryAcquire()) return Promise.resolve();
    return new Promise<void>((resolve, reject) => {
      const waiter = () => {
        signal?.removeEventListener("abort", onAbort);
        resolve();
      };
      const onAbort = () => {
        const i = this.waiters.indexOf(waiter);
        if (i >= 0) this.waiters.splice(i, 1);
        reject(new Error("aborted"));
      };
      signal?.addEventListener("abort", onAbort, { once: true });
      this.waiters.push(waiter);
    });
  }

  release(): void {
    if (this.active <= 0) throw new Error("semaphore released more times than acquired");
    this.active--;
    this.drain();
  }

  async run<T>(fn: () => Promise<T>): Promise<T> {
    await this.acquire();
    try {
      return await fn();
    } finally {
      this.release();
    }
  }

  private drain(): void {
    while (this.active < this.cap && this.waiters.length > 0) {
      const next = this.waiters.shift();
      if (!next) break;
      this.active++;
      next();
    }
  }
}

/** Run fn over items with at most `limit` in flight; preserves result order. */
export async function mapPool<T, R>(items: readonly T[], limit: number, fn: (item: T, index: number) => Promise<R>): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const i = next++;
      results[i] = await fn(items[i] as T, i);
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, worker));
  return results;
}
