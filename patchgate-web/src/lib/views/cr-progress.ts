import "server-only";
import { Prisma, type DeploymentStatus } from "@prisma/client";
import { isOnline } from "@/lib/connector/policy";
import { currentWindow } from "@/lib/deploy/window";
import { withTenant } from "@/lib/tenancy";
import { crProgress, deploymentStage, nextWindowStart, type CrProgress, type JobStatus, type Stage } from "./story";

/**
 * Per-PC progress of one change request: a grouped count for the bar, then ONE page of PCs with a plain
 * state derived from the Deployment row and its latest install job (no per-PC queries; 50k targets work).
 */

export const CR_PC_FILTERS = ["all", "active", "failed", "done"] as const;
export type CrPcFilter = (typeof CR_PC_FILTERS)[number];
export const CR_PC_PAGE_SIZE = 50;

const FILTER_STATUSES: Record<CrPcFilter, DeploymentStatus[] | null> = {
  all: null,
  active: ["QUEUED", "SENDING", "SENT"],
  failed: ["FAILED", "TIMED_OUT"],
  done: ["SUCCEEDED"],
};
const INSTALL_TYPES = ["DEPLOY_WINDOWS", "DEPLOY_PACKAGE", "WU_INSTALL"] as const;

export function parseCrPcQuery(sp: Record<string, string | string[] | undefined>): { show: CrPcFilter; page: number } {
  const show = CR_PC_FILTERS.find((f) => f === sp.show) ?? "all";
  const page = Number.parseInt(typeof sp.page === "string" ? sp.page : "", 10);
  return { show, page: Number.isFinite(page) && page > 0 ? Math.min(page, 10_000) : 1 };
}

export interface CrPcRow {
  deploymentId: string;
  endpointId: string;
  hostname: string;
  site: string | null;
  attempts: number;
  finishedAt: Date | null;
  stage: Stage;
}

export interface CrProgressView {
  progress: CrProgress;
  counts: Record<CrPcFilter, number>;
  rows: CrPcRow[];
  page: number;
  pages: number;
  window: { open: boolean; nextAt: Date | null } | null;
}

export async function loadCrProgress(tenantId: string, crId: string, query: { show: CrPcFilter; page: number }, now = new Date()): Promise<CrProgressView> {
  return withTenant(tenantId, async (tx) => {
    const cr = await tx.changeRequest.findFirst({ where: { id: crId, tenantId }, select: { window: { select: { cron: true, durationMin: true, timezone: true } } } });
    const grouped = await tx.deployment.groupBy({ by: ["status"], where: { tenantId, changeRequestId: crId }, _count: { _all: true } });
    const byStatus = Object.fromEntries(grouped.map((g) => [g.status, g._count._all])) as Partial<Record<DeploymentStatus, number>>;
    const sum = (s: DeploymentStatus[] | null) => (s ? s : (Object.keys(byStatus) as DeploymentStatus[])).reduce((n, k) => n + (byStatus[k] ?? 0), 0);
    const counts = Object.fromEntries(CR_PC_FILTERS.map((f) => [f, sum(FILTER_STATUSES[f])])) as Record<CrPcFilter, number>;

    const pages = Math.max(1, Math.ceil(counts[query.show] / CR_PC_PAGE_SIZE));
    const page = Math.min(query.page, pages);
    const statuses = FILTER_STATUSES[query.show];
    const deployments = await tx.deployment.findMany({
      where: { tenantId, changeRequestId: crId, ...(statuses ? { status: { in: statuses } } : {}) },
      orderBy: [{ endpoint: { hostname: "asc" } }, { id: "asc" }],
      skip: (page - 1) * CR_PC_PAGE_SIZE,
      take: CR_PC_PAGE_SIZE,
      include: { endpoint: { select: { id: true, hostname: true, site: true, connectorId: true } } },
    });
    const jobs = deployments.length
      ? await tx.connectorJob.findMany({
          where: { tenantId, deploymentId: { in: deployments.map((d) => d.id) }, type: { in: [...INSTALL_TYPES] } },
          orderBy: { createdAt: "desc" },
          select: { deploymentId: true, status: true, notBefore: true },
        })
      : [];
    const connectors = await tx.connector.findMany({ where: { tenantId, status: "ACTIVE" }, select: { id: true, lastSeenAt: true } });
    const online = new Map(connectors.map((c) => [c.id, isOnline(c.lastSeenAt, now)]));

    const w = cr?.window ?? null;
    const window = w ? { open: currentWindow(w, now) !== null, nextAt: nextWindowStart(w, now) } : null;
    return {
      progress: crProgress(byStatus),
      counts,
      page,
      pages,
      window,
      rows: deployments.map((d) => {
        const job = jobs.find((j) => j.deploymentId === d.id) ?? null;
        const connectorId = d.connectorId ?? d.endpoint.connectorId;
        return {
          deploymentId: d.id,
          endpointId: d.endpoint.id,
          hostname: d.endpoint.hostname,
          site: d.endpoint.site,
          attempts: d.attempts,
          finishedAt: d.finishedAt,
          stage: deploymentStage({
            status: d.status,
            note: d.note,
            error: d.error,
            failureKind: d.failureKind,
            windowOpen: window ? window.open : null,
            nextWindowAt: window?.nextAt ?? null,
            connectorOnline: connectorId ? (online.get(connectorId) ?? null) : null,
            job: job ? { status: job.status as JobStatus, notBefore: job.notBefore } : null,
            now,
          }),
        };
      }),
    };
  });
}

export interface CrAuditEvent {
  seq: bigint;
  ts: Date;
  actor: string;
  action: string;
  entity: string;
}

/** The request's own events + its deployments' events (sub-select: no id list, any number of PCs). */
export async function loadCrAudit(tenantId: string, crId: string, limit = 200): Promise<CrAuditEvent[]> {
  return withTenant(tenantId, (tx) =>
    tx.$queryRaw<CrAuditEvent[]>(Prisma.sql`
      SELECT a."seq", a."ts", a."actor", a."action", a."entity" FROM "AuditEvent" a
       WHERE a."tenantId" = ${tenantId}
         AND ((a."entity" = 'ChangeRequest' AND a."entityId" = ${crId})
           OR (a."entity" = 'Deployment' AND a."entityId" IN (SELECT d."id" FROM "Deployment" d WHERE d."tenantId" = ${tenantId} AND d."changeRequestId" = ${crId})))
       ORDER BY a."seq" ASC
       LIMIT ${limit}`),
  );
}
