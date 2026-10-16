import "server-only";
import { Prisma } from "@prisma/client";
import { listConnectors } from "@/lib/connector/admin";
import { directTacticalConfig, legacyTacticalTenantId } from "@/lib/tactical/from-env";
import { withTenant, type Tx } from "@/lib/tenancy";
import { compareVersions } from "@/lib/thirdparty/version";

/**
 * Shared read-model rules of the patch-story screens. "Missing" means the same thing everywhere:
 * an EndpointPatchState NEEDED or FAILED (a failed install is still missing) on a LIVE patch
 * (not superseded) that the bank can see — Windows updates, Tactical agent upgrades, and only the
 * third-party apps the bank has enabled (TenantApp), exactly like the Patches page.
 */

export const MISSING_STATUSES = ["NEEDED", "FAILED"] as const;

/** Prisma filter: a missing, visible patch state of `tenantId`. */
export function missingStateWhere(tenantId: string): Prisma.EndpointPatchStateWhereInput {
  return {
    tenantId,
    status: { in: [...MISSING_STATUSES] },
    patch: { supersededById: null, OR: [{ kind: { not: "THIRD_PARTY" } }, { appVersion: { app: { tenants: { some: { tenantId } } } } }] },
  };
}

/** Prisma filter: a live patch the bank can see (catalog rows are shared). */
export function visiblePatchWhere(tenantId: string): Prisma.PatchWhereInput {
  return { OR: [{ kind: { not: "THIRD_PARTY" } }, { appVersion: { app: { tenants: { some: { tenantId } } } } }] };
}

/** SQL twin of missingStateWhere for state rows aliased `s` joined to patches aliased `p`. */
export function missingStateSql(tenantId: string): Prisma.Sql {
  return Prisma.sql`s."tenantId" = ${tenantId} AND s."status" IN ('NEEDED', 'FAILED') AND p."supersededById" IS NULL
    AND (p."kind" <> 'THIRD_PARTY' OR EXISTS (
      SELECT 1 FROM "AppVersion" v JOIN "TenantApp" ta ON ta."appId" = v."appId" AND ta."tenantId" = ${tenantId}
       WHERE v."id" = p."appVersionId"))`;
}

/** The Tactical agent version PCs should run: the highest live AGENT_UPGRADE patch (same rule as the ingest). */
export async function agentTarget(tx: Tx): Promise<{ patchId: string; version: string } | null> {
  const live = await tx.patch.findMany({ where: { kind: "AGENT_UPGRADE", supersededById: null, agentVersion: { not: null } }, select: { id: true, agentVersion: true } });
  const best = live.reduce<(typeof live)[number] | null>((b, p) => (!b || compareVersions(p.agentVersion!, b.agentVersion!) > 0 ? p : b), null);
  return best?.agentVersion ? { patchId: best.id, version: best.agentVersion } : null;
}

// ---------------------------------------------------------------------------------------------
// Where the bank's PCs come from (for empty states that explain themselves)
// ---------------------------------------------------------------------------------------------

export interface FleetConnector {
  id: string;
  name: string;
  online: boolean;
  lastSeenAt: Date | null;
  tacticalReachable: boolean | null;
  tacticalAgents: number | null;
  tacticalError: string | null;
  endpoints: number;
  lastSync: { at: Date; agents: number | null } | null;
}

export interface FleetSource {
  bankName: string;
  /** the bank is served by the env-configured direct Tactical link (no connector) */
  direct: boolean;
  connectors: FleetConnector[];
  windowsUpdateSource: "PATCHGATE" | "WSUS";
  /** newest verified Microsoft offline scan catalog (needed for the daily WU_SCAN) */
  scanCatalogVerifiedAt: Date | null;
}

function agentsInResult(result: Prisma.JsonValue | null): number | null {
  const r = (result as { result?: { agents?: unknown } } | null)?.result?.agents;
  if (typeof r === "number") return r; // compacted after it was applied
  return Array.isArray(r) ? r.length : null;
}

/** Connectors (health from their heartbeats), their last agent sync, and the Windows update source. */
export async function loadFleetSource(tenantId: string, now = new Date()): Promise<FleetSource> {
  const connectors = (await listConnectors({ kind: "tenant", tenantId }, now)).filter((c) => c.status === "ACTIVE");
  const extra = await withTenant(tenantId, async (tx) => {
    const tenant = await tx.tenant.findUnique({ where: { id: tenantId }, select: { name: true, windowsUpdateSource: true } });
    const syncs = await Promise.all(
      connectors.map((c) =>
        tx.connectorJob.findFirst({
          where: { tenantId, connectorId: c.id, type: "SYNC_AGENTS", status: "SUCCEEDED" },
          orderBy: { completedAt: "desc" },
          select: { completedAt: true, result: true },
        }),
      ),
    );
    const cab = await tx.wsusScanCab.findFirst({ where: { verification: "VERIFIED", repoPath: { not: null } }, orderBy: { createdAt: "desc" }, select: { createdAt: true } });
    return { tenant, syncs, cab };
  });
  return {
    bankName: extra.tenant?.name ?? "This bank",
    direct: tenantId === legacyTacticalTenantId() && directTacticalConfig() !== null && connectors.length === 0,
    windowsUpdateSource: extra.tenant?.windowsUpdateSource ?? "PATCHGATE",
    scanCatalogVerifiedAt: extra.cab?.createdAt ?? null,
    connectors: connectors.map((c, i) => {
      const sync = extra.syncs[i];
      return {
        id: c.id,
        name: c.name,
        online: c.online,
        lastSeenAt: c.lastSeenAt,
        tacticalReachable: c.heartbeat ? c.heartbeat.tactical.reachable : null,
        tacticalAgents: c.heartbeat?.tactical.agents ?? null,
        tacticalError: c.heartbeat?.tactical.error ?? null,
        endpoints: c.endpoints,
        lastSync: sync?.completedAt ? { at: sync.completedAt, agents: agentsInResult(sync.result) } : null,
      };
    }),
  };
}
