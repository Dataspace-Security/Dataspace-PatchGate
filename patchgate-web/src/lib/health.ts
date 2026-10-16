import "server-only";
import { constants } from "node:fs";
import { access, mkdir } from "node:fs/promises";
import type { Prisma } from "@prisma/client";
import { prisma } from "@/lib/db";
import { env } from "@/lib/env";
import { anyChainExportStale } from "@/lib/audit/export";
import { auditChainsHealthy } from "@/lib/audit/verify-incremental";
import { repoQuotaStatus } from "@/lib/winupdate/quota";
import { notificationsConfigured } from "@/lib/notify/deliver";

/** Export older than this (with a SIEM configured) means the SIEM has stopped receiving the chain head. */
export const SIEM_STALE_MINUTES = 15;

export interface Readiness {
  ready: boolean; // false → 503: take this instance out of rotation
  checks: {
    database: boolean;
    migrations: boolean;
    repository: boolean;
    auditChain: boolean | null; // null = not checked (DB down / no verification run yet)
    siemExport: boolean | null; // null = no SIEM configured (dev)
    repoQuota: boolean | null; // false = repository over quota (downloads paused); null = never measured / DB down
    notifications: boolean; // report-only: false = SMTP not configured (alerts are recorded but not e-mailed)
  };
}

async function safe<T>(fn: () => Promise<T>, fallback: T): Promise<T> {
  try {
    return await fn();
  } catch {
    return fallback;
  }
}

/**
 * Every migration has a finished, non-rolled-back row (an old rolled-back attempt that was re-applied later
 * is fine — normal after `prisma migrate resolve --rolled-back`), and no attempt is still running / failed
 * (unfinished and not rolled back).
 */
export async function migrationsComplete(db: Pick<Prisma.TransactionClient, "$queryRaw">): Promise<boolean> {
  const rows = await db.$queryRaw<{ missing: bigint; pending: bigint }[]>`
    SELECT
      (SELECT COUNT(*) FROM (SELECT migration_name FROM "_prisma_migrations"
                              GROUP BY migration_name
                             HAVING COUNT(*) FILTER (WHERE finished_at IS NOT NULL AND rolled_back_at IS NULL) = 0) m) AS missing,
      (SELECT COUNT(*) FROM "_prisma_migrations" WHERE finished_at IS NULL AND rolled_back_at IS NULL) AS pending`;
  return Number(rows[0]?.missing ?? 1) === 0 && Number(rows[0]?.pending ?? 1) === 0;
}

/**
 * Readiness = can serve requests safely (DB reachable, schema fully migrated, repo writable).
 * Audit-chain integrity, SIEM freshness and the repository quota are reported for monitoring (alert!) but do not take
 * the instance out of rotation — operators need the UI to investigate. Booleans only: no details leak.
 */
export async function readiness(): Promise<Readiness> {
  const e = env();
  const database = await safe(async () => (await prisma.$queryRaw<{ ok: number }[]>`SELECT 1 AS ok`).length === 1, false);
  const migrations = database
    ? await safe(() => migrationsComplete(prisma), false)
    : false;
  const repository = await safe(async () => {
    await mkdir(e.REPO_DIR, { recursive: true });
    await access(e.REPO_DIR, constants.R_OK | constants.W_OK);
    return true;
  }, false);
  // Verdict of the worker's incremental verification (verify-incremental.ts): a cheap read, never a scan.
  const auditChain = database ? await safe(() => auditChainsHealthy(), false) : null;
  const siemExport = !e.SIEM_SYSLOG_URL
    ? null
    : database
      ? await safe(async () => !(await anyChainExportStale(SIEM_STALE_MINUTES)), false)
      : false;
  // Report-only (like auditChain): an over-quota repository pauses downloads, it does not stop serving.
  const repoQuota = database ? await safe(async () => (await repoQuotaStatus())?.ok ?? null, false) : null;
  return { ready: database && migrations && repository, checks: { database, migrations, repository, auditChain, siemExport, repoQuota, notifications: notificationsConfigured() } };
}
