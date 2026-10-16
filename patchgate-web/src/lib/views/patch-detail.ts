import "server-only";
import { Prisma } from "@prisma/client";
import { eligibilityErrors } from "@/lib/approvals/eligibility";
import { enabledAppIds, toEligible } from "@/lib/approvals/load-eligible";
import { withTenant } from "@/lib/tenancy";
import { MISSING_STATUSES } from "./common";
import type { Severity } from "./story";

/**
 * One patch through the bank's eyes: what it is and where it comes from, whether it may be requested now
 * (verification / quarantine — the same eligibility rules the change-request service enforces), and which
 * of the bank's PCs need it vs have it, per ring. Third-party packages the bank has not enabled are
 * "not found", exactly as on the Patches list.
 */

const NEEDING_LIMIT = 50;

export type Verification = "PENDING" | "HELD" | "VERIFIED" | "REJECTED";

export type PatchTrust =
  | {
      kind: "windows";
      viaWsus: boolean;
      catalogState: "PENDING" | "RESOLVED" | "UNRESOLVABLE" | "UNKNOWN";
      resolveError: string | null;
      files: { name: string; verification: Verification; availableAt: Date | null; sizeBytes: bigint | null; problem: string | null }[];
    }
  | {
      kind: "app";
      app: string;
      wingetId: string;
      version: string;
      verification: Verification;
      signerOrg: string | null;
      holdReason: string | null;
      rejectReason: string | null;
      availableAt: Date | null;
      decidedBy: string | null;
    }
  | { kind: "agent"; version: string | null; builds: { assetName: string; verification: Verification }[] };

export interface RingCoverage {
  ringId: string | null;
  name: string;
  needed: number;
  installed: number;
  notApplicable: number;
}

export interface PatchDetail {
  patch: {
    id: string;
    title: string;
    kb: string | null;
    kind: "WINDOWS" | "THIRD_PARTY" | "AGENT_UPGRADE";
    severity: Severity;
    classification: string | null;
    cves: string[];
    releasedAt: Date | null;
    createdAt: Date;
  };
  supersededBy: { id: string; title: string } | null;
  trust: PatchTrust;
  /** null = may be put into a change request now */
  blockedReason: string | null;
  rings: RingCoverage[];
  totals: { needed: number; installed: number; bankPcs: number };
  needing: { endpointId: string; hostname: string; site: string | null; ring: string | null; failed: boolean }[];
}

interface CoverageRow {
  ringId: string | null;
  status: string;
  n: number;
}

export async function loadPatchDetail(tenantId: string, patchId: string, now = new Date()): Promise<PatchDetail | null> {
  return withTenant(tenantId, async (tx) => {
    const p = await tx.patch.findUnique({ where: { id: patchId }, include: { appVersion: { include: { app: true } }, supersededBy: { select: { id: true, title: true } } } });
    if (!p) return null;
    const enabled = await enabledAppIds(tx, tenantId);
    if (p.kind === "THIRD_PARTY" && (!p.appVersion || !enabled.has(p.appVersion.appId))) return null;

    const [eligible] = await toEligible([p], enabled, tx);
    const blocked = eligibilityErrors([eligible], now)[0];

    let trust: PatchTrust;
    if (p.kind === "WINDOWS") {
      const tenant = await tx.tenant.findUnique({ where: { id: tenantId }, select: { windowsUpdateSource: true } });
      const wu = await tx.winUpdate.findUnique({
        where: { id: p.externalId.toLowerCase() },
        select: { catalogState: true, resolveError: true, files: { orderBy: { ordinal: "asc" }, select: { name: true, verification: true, availableAt: true, sizeBytes: true, rejectReason: true, lastError: true } } },
      });
      trust = {
        kind: "windows",
        viaWsus: tenant?.windowsUpdateSource === "WSUS",
        catalogState: wu?.catalogState ?? "UNKNOWN",
        resolveError: wu?.resolveError ?? null,
        files: (wu?.files ?? []).map((f) => ({ name: f.name, verification: f.verification, availableAt: f.availableAt, sizeBytes: f.sizeBytes, problem: f.rejectReason ?? f.lastError })),
      };
    } else if (p.kind === "THIRD_PARTY") {
      const v = p.appVersion!;
      trust = {
        kind: "app",
        app: v.app.displayName,
        wingetId: v.app.wingetId,
        version: v.version,
        verification: v.verification,
        signerOrg: v.signerOrg,
        holdReason: v.holdReason,
        rejectReason: v.rejectReason,
        availableAt: v.availableAt,
        decidedBy: v.decidedBy,
      };
    } else {
      const builds = p.agentVersion
        ? await tx.mirroredRelease.findMany({ where: { component: "TACTICAL_AGENT", version: p.agentVersion }, orderBy: { assetName: "asc" }, select: { assetName: true, verification: true } })
        : [];
      trust = { kind: "agent", version: p.agentVersion, builds };
    }

    const coverage = await tx.$queryRaw<CoverageRow[]>(Prisma.sql`
      SELECT e."ringId" AS "ringId", s."status"::text AS "status", count(*)::int AS "n"
        FROM "EndpointPatchState" s JOIN "Endpoint" e ON e."id" = s."endpointId" AND e."tenantId" = ${tenantId}
       WHERE s."tenantId" = ${tenantId} AND s."patchId" = ${patchId}
       GROUP BY e."ringId", s."status"`);
    const ringRows = await tx.ring.findMany({ where: { tenantId }, orderBy: { order: "asc" }, select: { id: true, name: true } });
    const cell = (ringId: string | null, statuses: readonly string[]) => coverage.filter((c) => c.ringId === ringId && statuses.includes(c.status)).reduce((n, c) => n + c.n, 0);
    const toCoverage = (ringId: string | null, name: string): RingCoverage => ({
      ringId,
      name,
      needed: cell(ringId, MISSING_STATUSES),
      installed: cell(ringId, ["INSTALLED"]),
      notApplicable: cell(ringId, ["NOT_APPLICABLE"]),
    });
    const rings = ringRows.map((r) => toCoverage(r.id, r.name));
    const none = toCoverage(null, "Not in a ring");
    if (none.needed + none.installed + none.notApplicable > 0) rings.push(none);

    const needing = await tx.endpointPatchState.findMany({
      where: { tenantId, patchId, status: { in: [...MISSING_STATUSES] } },
      orderBy: { endpoint: { hostname: "asc" } },
      take: NEEDING_LIMIT,
      select: { status: true, endpoint: { select: { id: true, hostname: true, site: true, ring: { select: { name: true } } } } },
    });

    return {
      patch: { id: p.id, title: p.title, kb: p.kb, kind: p.kind, severity: p.severity, classification: p.classification, cves: p.cves, releasedAt: p.releasedAt, createdAt: p.createdAt },
      supersededBy: p.supersededBy,
      trust,
      blockedReason: blocked ? blocked.split(": ").slice(1).join(": ") || blocked : null,
      rings,
      totals: {
        needed: rings.reduce((n, r) => n + r.needed, 0),
        installed: rings.reduce((n, r) => n + r.installed, 0),
        bankPcs: await tx.endpoint.count({ where: { tenantId } }),
      },
      needing: needing.map((s) => ({ endpointId: s.endpoint.id, hostname: s.endpoint.hostname, site: s.endpoint.site, ring: s.endpoint.ring?.name ?? null, failed: s.status === "FAILED" })),
    };
  });
}
