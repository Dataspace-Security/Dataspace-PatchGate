import "server-only";
import { randomUUID } from "node:crypto";
import { prisma } from "@/lib/db";
import { log } from "@/lib/log";

/**
 * Cluster-safe mutual exclusion for scheduled jobs (works across processes/instances).
 * A lease is taken atomically only if absent or expired; a crashed holder's lease simply expires.
 */
export async function acquireLease(name: string, ttlMs: number): Promise<string | null> {
  const holder = randomUUID();
  const expiresAt = new Date(Date.now() + ttlMs);
  const rows = await prisma.$queryRaw<{ holder: string }[]>`
    INSERT INTO "WorkerLease" ("name", "holder", "expiresAt") VALUES (${name}, ${holder}, ${expiresAt})
    ON CONFLICT ("name") DO UPDATE SET "holder" = EXCLUDED."holder", "expiresAt" = EXCLUDED."expiresAt"
    WHERE "WorkerLease"."expiresAt" < now()
    RETURNING "holder"`;
  return rows[0]?.holder === holder ? holder : null;
}

/** Extend a lease we still hold; false when it was lost (expired and taken over). */
export async function renewLease(name: string, holder: string, ttlMs: number): Promise<boolean> {
  const r = await prisma.workerLease.updateMany({ where: { name, holder }, data: { expiresAt: new Date(Date.now() + ttlMs) } });
  return r.count === 1;
}

export async function releaseLease(name: string, holder: string): Promise<void> {
  await prisma.workerLease.deleteMany({ where: { name, holder } });
}

/**
 * Run fn under a lease; returns null (without running) if another run holds it. While fn runs the lease
 * is renewed every ttl/3, so a long (but alive) run is never overtaken by a second one; a crashed holder
 * stops renewing and its lease expires after ttlMs.
 */
export async function withLease<T>(name: string, ttlMs: number, fn: () => Promise<T>): Promise<T | null> {
  const holder = await acquireLease(name, ttlMs);
  if (!holder) return null;
  const timer = setInterval(() => {
    renewLease(name, holder, ttlMs)
      .then((ok) => {
        if (!ok) log.warn("lease.lost", { name });
      })
      .catch((err: unknown) => log.warn("lease.renew_failed", { name, err }));
  }, Math.max(1_000, Math.floor(ttlMs / 3)));
  timer.unref?.();
  try {
    return await fn();
  } finally {
    clearInterval(timer);
    await releaseLease(name, holder);
  }
}
