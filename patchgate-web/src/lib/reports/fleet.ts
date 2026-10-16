import "server-only";
import { Prisma } from "@prisma/client";
import type { Tx } from "@/lib/tenancy/db";
import type { AgeBucket } from "./period";
import type { FleetSummary, GapRow, MissingPatchRow, RingRow } from "./types";

/**
 * Fleet compliance aggregates of ONE bank, computed in the database (GROUP BY / COUNT, never row-by-row in
 * Node) so they stay fast at 50k endpoints and millions of patch states: every query starts from
 * EndpointPatchState("tenantId", "status", "patchId") (index added for reports).
 *
 * Definitions (shown on the report):
 *  - a "gap" = an applicable, not superseded CRITICAL / IMPORTANT patch in state NEEDED or FAILED;
 *  - an endpoint is compliant when it has been scanned (inventory or Windows-update scan) and has no gap;
 *  - gap age = days since the patch's release (unknown when the catalog has no release date).
 * Compliance is a point-in-time snapshot at generation time (patch states are current state, not history).
 */

const DAY_MS = 86_400_000;

function gapWhere(tenantId: string): Prisma.Sql {
  return Prisma.sql`s."tenantId" = ${tenantId} AND s."status" IN ('NEEDED', 'FAILED') AND p."severity" IN ('CRITICAL', 'IMPORTANT') AND p."supersededById" IS NULL`;
}

function pct(n: number, d: number): number | null {
  return d > 0 ? Math.round((n / d) * 1000) / 10 : null;
}

export async function fleetAndRings(tx: Tx, tenantId: string): Promise<{ fleet: Omit<FleetSummary, "criticalMissing" | "importantMissing">; rings: RingRow[] }> {
  const rows = await tx.$queryRaw<{ ringId: string | null; endpoints: number; scanned: number; compliant: number }[]>`
    WITH gap AS (
      SELECT DISTINCT s."endpointId" FROM "EndpointPatchState" s JOIN "Patch" p ON p."id" = s."patchId"
       WHERE ${gapWhere(tenantId)}
    )
    SELECT e."ringId" AS "ringId",
           count(*)::int AS "endpoints",
           count(*) FILTER (WHERE e."lastScanAt" IS NOT NULL OR e."lastWuScanAt" IS NOT NULL)::int AS "scanned",
           count(*) FILTER (WHERE (e."lastScanAt" IS NOT NULL OR e."lastWuScanAt" IS NOT NULL) AND g."endpointId" IS NULL)::int AS "compliant"
      FROM "Endpoint" e LEFT JOIN gap g ON g."endpointId" = e."id"
     WHERE e."tenantId" = ${tenantId}
     GROUP BY e."ringId"`;
  const ringNames = new Map((await tx.ring.findMany({ where: { tenantId }, select: { id: true, name: true, order: true } })).map((r) => [r.id, r]));
  const rings: RingRow[] = rows
    .map((r) => ({
      ringId: r.ringId,
      ring: r.ringId ? (ringNames.get(r.ringId)?.name ?? r.ringId) : "(no ring)",
      endpoints: r.endpoints,
      scanned: r.scanned,
      compliant: r.compliant,
      compliancePct: pct(r.compliant, r.scanned),
    }))
    .sort((a, b) => (a.ringId ? (ringNames.get(a.ringId)?.order ?? 999) : 1000) - (b.ringId ? (ringNames.get(b.ringId)?.order ?? 999) : 1000));
  const endpoints = rings.reduce((n, r) => n + r.endpoints, 0);
  const scanned = rings.reduce((n, r) => n + r.scanned, 0);
  const compliant = rings.reduce((n, r) => n + r.compliant, 0);
  return { fleet: { endpoints, scanned, compliant, compliancePct: pct(compliant, scanned) }, rings };
}

export async function gapsByAge(tx: Tx, tenantId: string, asOf: Date): Promise<GapRow[]> {
  const b8 = new Date(asOf.getTime() - 8 * DAY_MS);
  const b31 = new Date(asOf.getTime() - 31 * DAY_MS);
  const b91 = new Date(asOf.getTime() - 91 * DAY_MS);
  const rows = await tx.$queryRaw<{ severity: "CRITICAL" | "IMPORTANT"; bucket: AgeBucket; missing: number; endpoints: number }[]>`
    SELECT p."severity"::text AS "severity",
           CASE WHEN p."releasedAt" IS NULL THEN 'unknown'
                WHEN p."releasedAt" > ${b8} THEN '0-7'
                WHEN p."releasedAt" > ${b31} THEN '8-30'
                WHEN p."releasedAt" > ${b91} THEN '31-90'
                ELSE '>90' END AS "bucket",
           count(*)::int AS "missing",
           count(DISTINCT s."endpointId")::int AS "endpoints"
      FROM "EndpointPatchState" s JOIN "Patch" p ON p."id" = s."patchId"
     WHERE ${gapWhere(tenantId)}
     GROUP BY 1, 2`;
  return rows;
}

export async function topMissingPatches(tx: Tx, tenantId: string, limit = 20): Promise<MissingPatchRow[]> {
  return tx.$queryRaw<MissingPatchRow[]>`
    SELECT p."id" AS "patchId", p."title", p."kb", p."kind"::text AS "kind", p."severity"::text AS "severity", p."releasedAt" AS "releasedAt",
           count(*)::int AS "endpoints"
      FROM "EndpointPatchState" s JOIN "Patch" p ON p."id" = s."patchId"
     WHERE s."tenantId" = ${tenantId} AND s."status" IN ('NEEDED', 'FAILED') AND p."supersededById" IS NULL
     GROUP BY p."id"
     ORDER BY count(*) DESC, CASE p."severity" WHEN 'CRITICAL' THEN 0 WHEN 'IMPORTANT' THEN 1 WHEN 'MODERATE' THEN 2 ELSE 3 END, p."id"
     LIMIT ${limit}`;
}

export interface NonCompliantRow {
  endpointId: string;
  hostname: string;
  site: string | null;
  ring: string | null;
  lastScanAt: Date | null;
  gaps: number;
  critical: number;
  oldestReleasedAt: Date | null;
}

/** One page of non-compliant endpoints (keyset pagination by endpoint id) — for the streamed CSV. */
export async function nonCompliantPage(tx: Tx, tenantId: string, afterId: string, take: number): Promise<NonCompliantRow[]> {
  return tx.$queryRaw<NonCompliantRow[]>`
    SELECT e."id" AS "endpointId", e."hostname", e."site", r."name" AS "ring", e."lastScanAt" AS "lastScanAt",
           count(*)::int AS "gaps",
           count(*) FILTER (WHERE p."severity" = 'CRITICAL')::int AS "critical",
           min(p."releasedAt") AS "oldestReleasedAt"
      FROM "EndpointPatchState" s
      JOIN "Patch" p ON p."id" = s."patchId"
      JOIN "Endpoint" e ON e."id" = s."endpointId"
      LEFT JOIN "Ring" r ON r."id" = e."ringId"
     WHERE ${gapWhere(tenantId)} AND s."endpointId" > ${afterId}
     GROUP BY e."id", r."name"
     ORDER BY e."id"
     LIMIT ${take}`;
}

export function missingTotals(gaps: readonly GapRow[]): { criticalMissing: number; importantMissing: number } {
  return {
    criticalMissing: gaps.filter((g) => g.severity === "CRITICAL").reduce((n, g) => n + g.missing, 0),
    importantMissing: gaps.filter((g) => g.severity === "IMPORTANT").reduce((n, g) => n + g.missing, 0),
  };
}
