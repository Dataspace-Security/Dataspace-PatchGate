import "server-only";
import { Prisma } from "@prisma/client";
import { chainName } from "@/lib/audit/service";
import type { Tx } from "@/lib/tenancy/db";
import { REPO_QUOTA_SOURCE, repoQuotaStatus } from "@/lib/winupdate/quota";
import { ageSec, type TenantRow } from "./collect-banks";
import type { AuditChainOps, FetchSourceOps, RepoQuotaOps, SiemChainOps } from "./types";

const DAY_MS = 86_400_000;
const GIB = 1024 ** 3;
export const PLATFORM_LABEL = "platform";

function labelFor(tenantId: string | null, tenants: ReadonlyMap<string, TenantRow>): string {
  return tenantId === null ? PLATFORM_LABEL : (tenants.get(tenantId)?.slug ?? tenantId);
}

/** Verdicts of the worker's incremental verification (one row per chain; never scans a chain). */
export async function loadAuditChains(tx: Tx, tenants: ReadonlyMap<string, TenantRow>): Promise<AuditChainOps[]> {
  const rows = await tx.auditVerifyCheckpoint.findMany({ orderBy: { chain: "asc" }, select: { chain: true, tenantId: true, valid: true, verifiedAt: true, problem: true } });
  return rows.map((r) => ({ chain: r.chain, label: labelFor(r.tenantId, tenants), valid: r.valid, verifiedAt: r.verifiedAt, problem: r.problem }));
}

interface SiemRow {
  tenantId: string | null;
  exportedAt: Date | null;
  oldestPending: Date | null;
}

/**
 * Export lag per chain: age of the oldest event after the last exported anchor. Two index lookups per chain
 * (AuditAnchor / AuditEvent by (tenantId, seq)) in a single statement.
 */
export async function loadSiemLag(tx: Tx, tenants: ReadonlyMap<string, TenantRow>, now: Date): Promise<SiemChainOps[]> {
  const rows = await tx.$queryRaw<SiemRow[]>(Prisma.sql`
    SELECT t."id" AS "tenantId", a."exportedAt", e."ts" AS "oldestPending"
      FROM "Tenant" t
      LEFT JOIN LATERAL (SELECT x."seq", x."exportedAt" FROM "AuditAnchor" x
                          WHERE x."tenantId" = t."id" AND x."eventCount" > 0 ORDER BY x."seq" DESC LIMIT 1) a ON true
      LEFT JOIN LATERAL (SELECT y."ts" FROM "AuditEvent" y
                          WHERE y."tenantId" = t."id" AND y."seq" > COALESCE(a."seq", 0) ORDER BY y."seq" ASC LIMIT 1) e ON true
    UNION ALL
    SELECT NULL, a."exportedAt", e."ts"
      FROM (SELECT 1) one
      LEFT JOIN LATERAL (SELECT x."seq", x."exportedAt" FROM "AuditAnchor" x
                          WHERE x."tenantId" IS NULL AND x."eventCount" > 0 ORDER BY x."seq" DESC LIMIT 1) a ON true
      LEFT JOIN LATERAL (SELECT y."ts" FROM "AuditEvent" y
                          WHERE y."tenantId" IS NULL AND y."seq" > COALESCE(a."seq", 0) ORDER BY y."seq" ASC LIMIT 1) e ON true`);
  return rows
    .map((r) => ({
      chain: chainName(r.tenantId),
      label: labelFor(r.tenantId, tenants),
      lastExportAt: r.exportedAt,
      pending: r.oldestPending !== null,
      lagSec: r.oldestPending ? (ageSec(r.oldestPending, now) ?? 0) : 0,
    }))
    .sort((a, b) => (a.label === PLATFORM_LABEL ? -1 : b.label === PLATFORM_LABEL ? 1 : a.label.localeCompare(b.label)));
}

/** "12.34 of 500.00 GB used…" (quota.ts message) → bytes used; null when unparseable. */
export function parseUsedBytes(message: string | null | undefined): number | null {
  const m = /^\s*([\d.]+) of [\d.]+ GB used/.exec(message ?? "");
  if (!m) return null;
  const gb = Number(m[1]);
  return Number.isFinite(gb) ? Math.round(gb * GIB) : null;
}

export async function loadRepoQuota(maxGb: number): Promise<RepoQuotaOps | null> {
  const s = await repoQuotaStatus();
  if (!s) return null;
  return { ok: s.ok, usedBytes: parseUsedBytes(s.message), quotaBytes: Math.round(maxGb * GIB), measuredAt: s.at };
}

interface FetchRow {
  source: string;
  runs24h: number;
  failed24h: number;
  lastSuccessAt: Date | null;
  lastFailureAt: Date | null;
}

/** Fetch runs by source family ("winget:<id>" → "winget"); the repository quota checks are reported separately. */
export async function loadFetchRuns(tx: Tx, now: Date): Promise<FetchSourceOps[]> {
  const since = new Date(now.getTime() - DAY_MS);
  return tx.$queryRaw<FetchRow[]>(Prisma.sql`
    SELECT split_part("source", ':', 1) AS "source",
           count(*) FILTER (WHERE "startedAt" >= ${since})::int AS "runs24h",
           count(*) FILTER (WHERE "startedAt" >= ${since} AND "ok" = false)::int AS "failed24h",
           max("startedAt") FILTER (WHERE "ok" = true) AS "lastSuccessAt",
           max("startedAt") FILTER (WHERE "ok" = false) AS "lastFailureAt"
      FROM "FetchRun"
     WHERE "source" <> ${REPO_QUOTA_SOURCE}
     GROUP BY 1
     ORDER BY 1`);
}

/** Packages waiting for a platform trust decision (shared catalog: not per bank). */
export async function loadHeldPackages(tx: Tx): Promise<Record<string, number>> {
  const where = { verification: "HELD" as const };
  return {
    app: await tx.appVersion.count({ where }),
    tactical: await tx.mirroredRelease.count({ where }),
    windows_update: await tx.winUpdateFile.count({ where }),
    scan_catalog: await tx.wsusScanCab.count({ where }),
  };
}
