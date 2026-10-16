import "server-only";
import type { Prisma } from "@prisma/client";
import { withTenant, type Tx } from "@/lib/tenancy";
import { agentTarget, missingStateWhere } from "./common";
import { STALE_SCAN_MS, pcStatus, type PcStatus } from "./story";

/**
 * Endpoints list: filters (search params), counts per filter, one page of PCs with their plain status.
 * Per-row numbers come from grouped counts over the PAGE's PCs only (no N+1, no full-fleet scan per row).
 */

export const ENDPOINT_FILTERS = ["all", "needs", "critical", "uptodate", "agent", "unscanned", "reboot"] as const;
export type EndpointFilter = (typeof ENDPOINT_FILTERS)[number];
export const ENDPOINTS_PAGE_SIZE = 50;

export interface EndpointQuery {
  show: EndpointFilter;
  /** ring id, "none" = not in a ring, null = any */
  ring: string | null;
  page: number;
  q: string;
}

const ID_RE = /^[A-Za-z0-9_-]{1,64}$/;

/** Parse untrusted search params (anything unknown falls back to the default). */
export function parseEndpointQuery(sp: Record<string, string | string[] | undefined>): EndpointQuery {
  const one = (k: string) => (typeof sp[k] === "string" ? (sp[k] as string) : "");
  const show = ENDPOINT_FILTERS.find((f) => f === one("show")) ?? "all";
  const ring = one("ring");
  const page = Number.parseInt(one("page"), 10);
  return {
    show,
    ring: ring === "none" || ID_RE.test(ring) ? ring : null,
    page: Number.isFinite(page) && page > 0 ? Math.min(page, 10_000) : 1,
    q: one("q").trim().slice(0, 100),
  };
}

export function endpointFilterWhere(tenantId: string, show: EndpointFilter, now: Date, agentPatchId: string | null): Prisma.EndpointWhereInput {
  const missing = missingStateWhere(tenantId);
  const stale = new Date(now.getTime() - STALE_SCAN_MS);
  switch (show) {
    case "all":
      return {};
    case "needs":
      return { lastScanAt: { not: null }, patchStates: { some: missing } };
    case "critical":
      return { lastScanAt: { not: null }, patchStates: { some: { ...missing, patch: { ...(missing.patch as Prisma.PatchWhereInput), severity: "CRITICAL" } } } };
    case "uptodate":
      return { lastScanAt: { not: null }, patchStates: { none: missing } };
    case "agent":
      return agentPatchId ? { patchStates: { some: { tenantId, patchId: agentPatchId, status: "NEEDED" } } } : { id: "__none__" };
    case "unscanned":
      return { OR: [{ lastScanAt: null }, { lastScanAt: { lt: stale } }] };
    case "reboot":
      return { rebootRequired: true };
  }
}

function baseWhere(tenantId: string, q: EndpointQuery): Prisma.EndpointWhereInput {
  return {
    tenantId,
    ...(q.ring === "none" ? { ringId: null } : q.ring ? { ringId: q.ring } : {}),
    ...(q.q ? { OR: [{ hostname: { contains: q.q, mode: "insensitive" } }, { site: { contains: q.q, mode: "insensitive" } }] } : {}),
  };
}

export interface EndpointRow {
  id: string;
  hostname: string;
  site: string | null;
  osName: string | null;
  agentVersion: string | null;
  goarch: string | null;
  ringId: string | null;
  lastScanAt: Date | null;
  rebootRequired: boolean;
  status: PcStatus;
  agentOutdated: boolean;
}

export interface EndpointList {
  rows: EndpointRow[];
  /** PCs matching the current filter */
  matching: number;
  /** all PCs of the bank */
  bankTotal: number;
  counts: Record<EndpointFilter, number>;
  page: number;
  pages: number;
  rings: { id: string; name: string }[];
  agentTarget: string | null;
}

async function perPcCounts(tx: Tx, tenantId: string, ids: string[], agentPatchId: string | null) {
  if (ids.length === 0) return { missing: new Map<string, number>(), critical: new Map<string, number>(), agent: new Set<string>() };
  const missing = missingStateWhere(tenantId);
  const all = await tx.endpointPatchState.groupBy({ by: ["endpointId"], where: { ...missing, endpointId: { in: ids } }, _count: { _all: true } });
  const crit = await tx.endpointPatchState.groupBy({
    by: ["endpointId"],
    where: { ...missing, endpointId: { in: ids }, patch: { ...(missing.patch as Prisma.PatchWhereInput), severity: "CRITICAL" } },
    _count: { _all: true },
  });
  const agent = agentPatchId
    ? await tx.endpointPatchState.findMany({ where: { tenantId, endpointId: { in: ids }, patchId: agentPatchId, status: "NEEDED" }, select: { endpointId: true } })
    : [];
  return {
    missing: new Map(all.map((r) => [r.endpointId, r._count._all])),
    critical: new Map(crit.map((r) => [r.endpointId, r._count._all])),
    agent: new Set(agent.map((a) => a.endpointId)),
  };
}

export async function loadEndpointList(tenantId: string, query: EndpointQuery, now = new Date()): Promise<EndpointList> {
  return withTenant(tenantId, async (tx) => {
    const agent = await agentTarget(tx);
    const agentPatchId = agent?.patchId ?? null;
    const base = baseWhere(tenantId, query);
    const counts = {} as Record<EndpointFilter, number>;
    for (const f of ENDPOINT_FILTERS) counts[f] = await tx.endpoint.count({ where: { AND: [base, endpointFilterWhere(tenantId, f, now, agentPatchId)] } });
    const matching = counts[query.show];
    const pages = Math.max(1, Math.ceil(matching / ENDPOINTS_PAGE_SIZE));
    const page = Math.min(query.page, pages);
    const eps = await tx.endpoint.findMany({
      where: { AND: [base, endpointFilterWhere(tenantId, query.show, now, agentPatchId)] },
      orderBy: [{ site: { sort: "asc", nulls: "last" } }, { hostname: "asc" }, { id: "asc" }],
      skip: (page - 1) * ENDPOINTS_PAGE_SIZE,
      take: ENDPOINTS_PAGE_SIZE,
      select: { id: true, hostname: true, site: true, osName: true, agentVersion: true, goarch: true, ringId: true, lastScanAt: true, rebootRequired: true },
    });
    const per = await perPcCounts(tx, tenantId, eps.map((e) => e.id), agentPatchId);
    const rings = await tx.ring.findMany({ where: { tenantId }, orderBy: { order: "asc" }, select: { id: true, name: true } });
    return {
      rows: eps.map((e) => ({
        ...e,
        status: pcStatus({ lastScanAt: e.lastScanAt, missing: per.missing.get(e.id) ?? 0, critical: per.critical.get(e.id) ?? 0 }),
        agentOutdated: per.agent.has(e.id),
      })),
      matching,
      bankTotal: query.ring || query.q ? await tx.endpoint.count({ where: { tenantId } }) : counts.all,
      counts,
      page,
      pages,
      rings,
      agentTarget: agent?.version ?? null,
    };
  });
}
