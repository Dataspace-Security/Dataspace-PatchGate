import "server-only";
import { Prisma } from "@prisma/client";
import { isOnline } from "@/lib/connector/policy";
import type { Tx } from "@/lib/tenancy/db";
import type { ComplianceOps, ConnectorOps, JobCount, OutboxCount } from "./types";

/**
 * Cross-bank aggregates for monitoring. Every function takes a withPlatform() transaction (RLS platform scope)
 * and returns grouped counts only — never rows per endpoint/job — so cost stays flat with 50 banks × 50k PCs.
 */

const DAY_MS = 86_400_000;

export function ageSec(from: Date | null | undefined, now: Date): number | null {
  return from ? Math.max(0, Math.round((now.getTime() - from.getTime()) / 1000)) : null;
}

export interface TenantRow {
  id: string;
  slug: string;
  name: string;
  active: boolean;
}

export function loadTenants(tx: Tx): Promise<TenantRow[]> {
  return tx.tenant.findMany({ orderBy: { name: "asc" }, select: { id: true, slug: true, name: true, active: true } });
}

function obj(v: unknown): Record<string, unknown> | null {
  return v !== null && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}

/** Fields of the stored heartbeat the dashboards need (stored JSON is treated as untrusted). */
export function heartbeatFacts(raw: unknown): Pick<ConnectorOps, "cacheFreeBytes" | "tacticalReachable" | "siemConfigured" | "siemOk"> {
  const hb = obj(raw);
  const cache = obj(hb?.cache);
  const tactical = obj(hb?.tactical);
  const siem = obj(hb?.siem);
  const free = cache?.freeBytes;
  return {
    cacheFreeBytes: typeof free === "number" && Number.isFinite(free) && free >= 0 ? free : null,
    tacticalReachable: typeof tactical?.reachable === "boolean" ? tactical.reachable : null,
    siemConfigured: typeof siem?.configured === "boolean" ? siem.configured : null,
    siemOk: typeof siem?.configured === "boolean" ? siem.configured && !siem.error : null,
  };
}

export interface ConnectorsByBank {
  active: Map<string, ConnectorOps[]>;
  revoked: Map<string, number>;
}

export async function loadConnectors(tx: Tx, now: Date): Promise<ConnectorsByBank> {
  const rows = await tx.connector.findMany({
    orderBy: [{ tenantId: "asc" }, { name: "asc" }],
    select: { id: true, tenantId: true, name: true, status: true, version: true, lastSeenAt: true, heartbeat: true },
  });
  const active = new Map<string, ConnectorOps[]>();
  const revoked = new Map<string, number>();
  for (const r of rows) {
    if (r.status !== "ACTIVE") {
      revoked.set(r.tenantId, (revoked.get(r.tenantId) ?? 0) + 1);
      continue;
    }
    const list = active.get(r.tenantId) ?? [];
    list.push({
      id: r.id,
      name: r.name,
      online: isOnline(r.lastSeenAt, now),
      lastSeenAt: r.lastSeenAt,
      lastSeenAgeSec: ageSec(r.lastSeenAt, now),
      version: r.version,
      ...heartbeatFacts(r.heartbeat),
    });
    active.set(r.tenantId, list);
  }
  return { active, revoked };
}

function pushTo<T>(m: Map<string, T[]>, key: string, v: T): void {
  const list = m.get(key) ?? [];
  list.push(v);
  m.set(key, list);
}

export interface JobBacklog {
  backlog: Map<string, JobCount[]>;
  oldestDue: Map<string, Date>;
}

/** Open jobs by type/status, and the oldest DUE queued job (jobs scheduled for a later window are not late). */
export async function loadJobBacklog(tx: Tx, now: Date): Promise<JobBacklog> {
  // Sequential: one interactive transaction = one connection.
  const grouped = await tx.connectorJob.groupBy({ by: ["tenantId", "type", "status"], where: { status: { in: ["QUEUED", "DELIVERED"] } }, _count: { _all: true } });
  const oldest = await tx.connectorJob.groupBy({ by: ["tenantId"], where: { status: "QUEUED", notBefore: { lte: now } }, _min: { notBefore: true } });
  const backlog = new Map<string, JobCount[]>();
  for (const g of grouped) pushTo(backlog, g.tenantId, { type: g.type, status: g.status, count: g._count._all });
  const oldestDue = new Map<string, Date>();
  for (const o of oldest) if (o._min.notBefore) oldestDue.set(o.tenantId, o._min.notBefore);
  return { backlog, oldestDue };
}

export interface JobOutcomes {
  failed: Map<string, JobCount[]>;
  succeeded: Map<string, number>;
}

export async function loadJobOutcomes24h(tx: Tx, now: Date): Promise<JobOutcomes> {
  const since = new Date(now.getTime() - DAY_MS);
  const grouped = await tx.connectorJob.groupBy({
    by: ["tenantId", "type", "status"],
    where: { status: { in: ["SUCCEEDED", "FAILED", "EXPIRED"] }, completedAt: { gte: since } },
    _count: { _all: true },
  });
  const failed = new Map<string, JobCount[]>();
  const succeeded = new Map<string, number>();
  for (const g of grouped) {
    if (g.status === "SUCCEEDED") succeeded.set(g.tenantId, (succeeded.get(g.tenantId) ?? 0) + g._count._all);
    else pushTo(failed, g.tenantId, { type: g.type, status: g.status, count: g._count._all });
  }
  return { failed, succeeded };
}

function byTenantStatus(rows: { tenantId: string; status: string; _count: { _all: number } }[]): Map<string, Record<string, number>> {
  const out = new Map<string, Record<string, number>>();
  for (const r of rows) out.set(r.tenantId, { ...(out.get(r.tenantId) ?? {}), [r.status]: r._count._all });
  return out;
}

export async function loadActiveDeployments(tx: Tx): Promise<Map<string, Record<string, number>>> {
  const rows = await tx.deployment.groupBy({ by: ["tenantId", "status"], where: { status: { in: ["QUEUED", "SENDING", "SENT"] } }, _count: { _all: true } });
  return byTenantStatus(rows);
}

export async function loadFinishedDeployments24h(tx: Tx, now: Date): Promise<Map<string, Record<string, number>>> {
  const rows = await tx.deployment.groupBy({
    by: ["tenantId", "status"],
    where: { status: { in: ["SUCCEEDED", "FAILED", "TIMED_OUT"] }, finishedAt: { gte: new Date(now.getTime() - DAY_MS) } },
    _count: { _all: true },
  });
  return byTenantStatus(rows);
}

export async function loadPendingApprovals(tx: Tx): Promise<Map<string, { count: number; oldest: Date | null }>> {
  const rows = await tx.changeRequest.groupBy({ by: ["tenantId"], where: { status: "PENDING_APPROVAL" }, _count: { _all: true }, _min: { submittedAt: true, createdAt: true } });
  return new Map(rows.map((r) => [r.tenantId, { count: r._count._all, oldest: r._min.submittedAt ?? r._min.createdAt }]));
}

/**
 * Compliance buckets for every bank in ONE grouped query (same rule as the bank dashboard: a PC is up to date
 * when it has reported and no live, visible patch is NEEDED/FAILED on it).
 */
export async function loadCompliance(tx: Tx): Promise<Map<string, ComplianceOps>> {
  const rows = await tx.$queryRaw<(ComplianceOps & { tenantId: string })[]>(Prisma.sql`
    SELECT e."tenantId" AS "tenantId",
           count(*)::int AS "total",
           count(*) FILTER (WHERE e."lastScanAt" IS NULL)::int AS "notScanned",
           count(*) FILTER (WHERE e."lastScanAt" IS NOT NULL AND m."endpointId" IS NULL)::int AS "upToDate",
           count(*) FILTER (WHERE e."lastScanAt" IS NOT NULL AND m."endpointId" IS NOT NULL AND NOT m."critical")::int AS "needs",
           count(*) FILTER (WHERE e."lastScanAt" IS NOT NULL AND m."critical")::int AS "critical",
           count(*) FILTER (WHERE e."lastScanAt" IS NOT NULL AND m."important")::int AS "important"
      FROM "Endpoint" e
      LEFT JOIN (
        SELECT s."endpointId",
               bool_or(p."severity" = 'CRITICAL') AS "critical",
               bool_or(p."severity" = 'IMPORTANT') AS "important"
          FROM "EndpointPatchState" s JOIN "Patch" p ON p."id" = s."patchId"
         WHERE s."status" IN ('NEEDED', 'FAILED') AND p."supersededById" IS NULL
           AND (p."kind" <> 'THIRD_PARTY' OR EXISTS (
                SELECT 1 FROM "AppVersion" v JOIN "TenantApp" ta ON ta."appId" = v."appId" AND ta."tenantId" = s."tenantId"
                 WHERE v."id" = p."appVersionId"))
         GROUP BY s."endpointId"
      ) m ON m."endpointId" = e."id"
     GROUP BY e."tenantId"`);
  return new Map(rows.map(({ tenantId, ...c }) => [tenantId, c]));
}

/** Candidate names of the notification outbox (added by the notifications work; feature-detected). */
const OUTBOX_TABLES = ["Notification", "NotificationOutbox"] as const;
/** Delivered / intentionally dropped: not backlog. */
const OUTBOX_DONE = new Set(["SENT", "DELIVERED", "SUCCEEDED", "DONE", "CANCELLED", "SKIPPED"]);
/** Given up: counted as backlog (needs a human) but not as "waiting" for the oldest-age gauge. */
const OUTBOX_DEAD = new Set(["DEAD", "FAILED"]);
const IDENT_RE = /^[A-Za-z_][A-Za-z0-9_]{0,62}$/;

export interface OutboxByBank {
  counts: Map<string, OutboxCount[]>;
  oldest: Map<string, Date>;
}

interface OutboxTable {
  table: string;
  statusType: string;
  hasCreatedAt: boolean;
}

async function findOutboxTable(tx: Tx): Promise<OutboxTable | null> {
  const cols = await tx.$queryRaw<{ table_name: string; column_name: string; udt_name: string }[]>(Prisma.sql`
    SELECT c.table_name, c.column_name, c.udt_name
      FROM information_schema.columns c
     WHERE c.table_schema = current_schema() AND c.table_name IN (${Prisma.join([...OUTBOX_TABLES])})
       AND c.column_name IN ('tenantId', 'status', 'createdAt')`);
  for (const table of OUTBOX_TABLES) {
    const mine = cols.filter((c) => c.table_name === table);
    const status = mine.find((c) => c.column_name === "status");
    if (!status || !mine.some((c) => c.column_name === "tenantId")) continue;
    return { table, statusType: status.udt_name, hasCreatedAt: mine.some((c) => c.column_name === "createdAt") };
  }
  return null;
}

/**
 * Undelivered notifications per bank; null when no outbox table exists yet. Filters on the enum's
 * not-done labels so the (status, nextAttemptAt) index serves the query.
 */
export async function loadOutbox(tx: Tx): Promise<OutboxByBank | null> {
  const t = await findOutboxTable(tx);
  if (!t || !IDENT_RE.test(t.table) || !IDENT_RE.test(t.statusType)) return null;
  const labels = await tx.$queryRaw<{ label: string }[]>(Prisma.sql`
    SELECT e.enumlabel AS label FROM pg_enum e JOIN pg_type ty ON ty.oid = e.enumtypid WHERE ty.typname = ${t.statusType}`);
  const open = labels.map((l) => l.label).filter((l) => !OUTBOX_DONE.has(l));
  const counts = new Map<string, OutboxCount[]>();
  const oldest = new Map<string, Date>();
  if (labels.length > 0 && open.length === 0) return { counts, oldest };
  // Identifiers: fixed allow-list (table) / catalog type name checked against IDENT_RE — never user input.
  const statusFilter = labels.length > 0 ? `"status" = ANY($1::"${t.statusType}"[])` : `NOT ("status"::text = ANY($1::text[]))`;
  const param = labels.length > 0 ? open : [...OUTBOX_DONE];
  const oldestCol = t.hasCreatedAt ? `min("createdAt")` : `NULL::timestamp`;
  const rows = await tx.$queryRawUnsafe<{ tenantId: string | null; status: string; count: number; oldest: Date | null }[]>(
    `SELECT "tenantId", "status"::text AS "status", count(*)::int AS "count", ${oldestCol} AS "oldest"
       FROM "${t.table}" WHERE ${statusFilter} GROUP BY 1, 2`,
    param,
  );
  for (const r of rows) {
    if (!r.tenantId) continue; // platform-level notifications are not a bank's backlog
    pushTo(counts, r.tenantId, { status: r.status, count: r.count });
    if (OUTBOX_DEAD.has(r.status)) continue;
    const prev = oldest.get(r.tenantId);
    if (r.oldest && (!prev || r.oldest < prev)) oldest.set(r.tenantId, r.oldest);
  }
  return { counts, oldest };
}
