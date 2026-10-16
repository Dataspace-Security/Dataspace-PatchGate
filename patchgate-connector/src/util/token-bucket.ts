/**
 * Token bucket shared by every download served from the package cache, so the total bandwidth the
 * connector puts on the bank LAN/WAN never exceeds the configured limit — no matter how many PCs pull.
 *
 * take(n) may drive the balance negative ("debt"); the caller then waits until the debt is repaid.
 * Concurrent callers therefore queue fairly in aggregate. A rate of null means unlimited.
 */

export interface Clock {
  now(): number; // ms
  sleep(ms: number): Promise<void>;
}

export const realClock: Clock = {
  now: () => performance.now(),
  sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
};

/** Megabits per second → bytes per second. */
export const mbpsToBytesPerSec = (mbps: number): number => (mbps * 1_000_000) / 8;

export class TokenBucket {
  private tokens: number;
  private last: number;
  private rate: number | null; // bytes per second
  private burst: number; // bytes

  constructor(
    bytesPerSec: number | null,
    private readonly clock: Clock = realClock,
    private readonly burstSeconds = 0.25,
  ) {
    this.rate = null;
    this.burst = 0;
    this.last = clock.now();
    this.tokens = 0;
    this.setRate(bytesPerSec);
  }

  get bytesPerSec(): number | null {
    return this.rate;
  }

  setRate(bytesPerSec: number | null): void {
    if (bytesPerSec !== null && !(Number.isFinite(bytesPerSec) && bytesPerSec > 0)) {
      throw new Error("rate must be a positive number or null");
    }
    this.refill();
    const wasUnlimited = this.rate === null;
    this.rate = bytesPerSec;
    this.burst = bytesPerSec === null ? 0 : Math.max(16 * 1024, bytesPerSec * this.burstSeconds);
    // Coming from "unlimited" the bucket starts full; otherwise keep the balance (including debt).
    this.tokens = wasUnlimited ? this.burst : Math.min(this.tokens, this.burst);
  }

  private refill(): void {
    const now = this.clock.now();
    if (this.rate !== null) {
      this.tokens = Math.min(this.burst, this.tokens + ((now - this.last) / 1000) * this.rate);
    }
    this.last = now;
  }

  /** Reserve n bytes; resolves when they may be sent. */
  async take(n: number): Promise<void> {
    if (n <= 0 || this.rate === null) return;
    this.refill();
    this.tokens -= n;
    if (this.tokens >= 0) return;
    const waitMs = (-this.tokens / this.rate) * 1000;
    await this.clock.sleep(Math.ceil(waitMs));
  }
}
