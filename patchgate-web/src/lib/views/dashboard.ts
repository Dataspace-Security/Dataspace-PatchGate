import "server-only";
import { Prisma } from "@prisma/client";
import { auditExportStatus } from "@/lib/audit/export";
import { connectorHealth } from "@/lib/connector/admin";
import { env } from "@/lib/env";
import { withTenant, type Tx } from "@/lib/tenancy";
import { agentTarget, loadFleetSource, missingStateSql, missingStateWhere, type FleetSource } from "./common";
import {
  EMPTY_BUCKETS,
  SEVERITY_LABEL,
  STALE_SCAN_MS,
  addBuckets,
  ofN,
  pickAttention,
  plural,
  rankMissingPatches,
  startOfMonthUtc,
  type AttentionItem,
  type ComplianceBuckets,
  type Severity,
} from "./story";

/**
 * "Patch status at a glance" for one bank: headline compliance, per-ring breakdown, what needs attention,
 * and the patch journey (scanned → needed → requested → approved → installing → confirmed).
 * Aggregates only (count / groupBy / one grouped SQL): the cost does not grow with list sizes, and no
 * query ever loads a row per PC (50k PCs per bank).
 */

export interface DashboardViewer {
  /** PatchGate platform admin (sees held packages for the shared catalog) */
  platformAdmin: boolean;
  /** may approve this bank's change requests (role + bank-approval policy) */
  canApprove: boolean;
}

export interface RingSummary {
  id: string | null;
  name: string;
  buckets: ComplianceBuckets;
}

export interface MissingPatchSummary {
  patchId: string;
  title: string;
  kb: string | null;
  kind: "WINDOWS" | "THIRD_PARTY" | "AGENT_UPGRADE";
  severity: Severity;
  pcs: number;
}

export interface JourneyStep {
  key: "scanned" | "needed" | "requested" | "approved" | "installing" | "confirmed";
  title: string;
  value: string;
  explanation: string;
  href: string;
}

export interface DashboardView {
  totals: ComplianceBuckets;
  rings: RingSummary[];
  scannedLast24h: number;
  topMissing: MissingPatchSummary[];
  distinctMissingPatches: number;
  criticalPatchesMissing: number;
  attention: AttentionItem[];
  journey: JourneyStep[];
  fleet: FleetSource;
}

interface RingRow {
  ringId: string | null;
  total: number;
  notScanned: number;
  upToDate: number;
  needs: number;
  critical: number;
}

/** Every PC in exactly one bucket, per ring (one grouped pass over the bank's PCs and missing states). */
async function ringBuckets(tx: Tx, tenantId: string): Promise<RingRow[]> {
  return tx.$queryRaw<RingRow[]>(Prisma.sql`
    SELECT e."ringId" AS "ringId",
           count(*)::int AS "total",
           count(*) FILTER (WHERE e."lastScanAt" IS NULL)::int AS "notScanned",
           count(*) FILTER (WHERE e."lastScanAt" IS NOT NULL AND m."endpointId" IS NULL)::int AS "upToDate",
           count(*) FILTER (WHERE e."lastScanAt" IS NOT NULL AND m."endpointId" IS NOT NULL AND NOT m."critical")::int AS "needs",
           count(*) FILTER (WHERE e."lastScanAt" IS NOT NULL AND m."critical")::int AS "critical"
      FROM "Endpoint" e
      LEFT JOIN (
        SELECT s."endpointId", bool_or(p."severity" = 'CRITICAL') AS "critical"
          FROM "EndpointPatchState" s JOIN "Patch" p ON p."id" = s."patchId"
         WHERE ${missingStateSql(tenantId)}
         GROUP BY s."endpointId"
      ) m ON m."endpointId" = e."id"
     WHERE e."tenantId" = ${tenantId}
     GROUP BY e."ringId"`);
}

async function missingPatches(tx: Tx, tenantId: string): Promise<MissingPatchSummary[]> {
  const grouped = await tx.endpointPatchState.groupBy({ by: ["patchId"], where: missingStateWhere(tenantId), _count: { _all: true } });
  if (grouped.length === 0) return [];
  const patches = await tx.patch.findMany({ where: { id: { in: grouped.map((g) => g.patchId) } }, select: { id: true, title: true, kb: true, kind: true, severity: true } });
  const byId = new Map(patches.map((p) => [p.id, p]));
  return rankMissingPatches(
    grouped.flatMap((g) => {
      const p = byId.get(g.patchId);
      return p ? [{ patchId: p.id, title: p.title, kb: p.kb, kind: p.kind, severity: p.severity, pcs: g._count._all }] : [];
    }),
  );
}

async function loadCounts(tenantId: string, viewer: DashboardViewer, now: Date) {
  const staleCutoff = new Date(now.getTime() - STALE_SCAN_MS);
  return withTenant(tenantId, async (tx) => {
    const rings = await tx.ring.findMany({ where: { tenantId }, orderBy: { order: "asc" }, select: { id: true, name: true } });
    const crByStatus = await tx.changeRequest.groupBy({ by: ["status"], where: { tenantId }, _count: { _all: true } });
    const inFlight = await tx.deployment.groupBy({
      by: ["changeRequestId"],
      where: { tenantId, status: { in: ["QUEUED", "SENDING", "SENT"] }, changeRequest: { status: "DEPLOYING" } },
      _count: { _all: true },
    });
    return {
      rings,
      ringRows: await ringBuckets(tx, tenantId),
      missing: await missingPatches(tx, tenantId),
      agent: await agentTarget(tx),
      scannedLast24h: await tx.endpoint.count({ where: { tenantId, lastScanAt: { gte: staleCutoff } } }),
      stale: await tx.endpoint.count({ where: { tenantId, OR: [{ lastScanAt: null }, { lastScanAt: { lt: staleCutoff } }] } }),
      reboot: await tx.endpoint.count({ where: { tenantId, rebootRequired: true } }),
      unassigned: await tx.endpoint.count({ where: { tenantId, ringId: null } }),
      crs: Object.fromEntries(crByStatus.map((c) => [c.status, c._count._all])) as Partial<Record<string, number>>,
      installing: inFlight.reduce((n, g) => n + g._count._all, 0),
      installingCrs: inFlight.length,
      confirmedThisMonth: await tx.deployment.count({ where: { tenantId, status: "SUCCEEDED", finishedAt: { gte: startOfMonthUtc(now) } } }),
      failedLast7d: await tx.deployment.count({ where: { tenantId, status: { in: ["FAILED", "TIMED_OUT"] }, finishedAt: { gte: new Date(now.getTime() - 7 * 86_400_000) } } }),
      held: viewer.platformAdmin
        ? (await tx.appVersion.count({ where: { verification: "HELD" } })) + (await tx.mirroredRelease.count({ where: { verification: "HELD" } }))
        : 0,
    };
  });
}

type Counts = Awaited<ReturnType<typeof loadCounts>>;

function patchLabel(p: MissingPatchSummary): string {
  return p.kb && !p.title.includes(p.kb) ? `${p.title} (${p.kb})` : p.title;
}

/** Candidates for "Needs attention" (pickAttention keeps the most important few). */
function attentionItems(c: Counts, totals: ComplianceBuckets, fleet: FleetSource, health: Awaited<ReturnType<typeof connectorHealth>>, viewer: DashboardViewer, siem: { configured: boolean; ok: boolean }): AttentionItem[] {
  const n = totals.total;
  const pending = c.crs.PENDING_APPROVAL ?? 0;
  const top = c.missing.filter((m) => m.kind !== "AGENT_UPGRADE");
  const agentRow = c.missing.find((m) => m.kind === "AGENT_UPGRADE" && m.patchId === c.agent?.patchId);
  const items: (AttentionItem | null | false | undefined)[] = [
    fleet.connectors.length === 0 && !fleet.direct && { key: "no-connector", priority: 0, tone: "warn", text: "No site connector is enrolled for this bank yet — no PC can be reached.", href: "/connectors" },
    health.offline.length > 0 && {
      key: "connector-offline",
      priority: 1,
      tone: "bad",
      text: `${ofN(health.offline.length, health.total)} site connectors offline: ${health.offline.map((o) => o.name).join(", ")}`,
      hint: "Jobs for their PCs wait until they reconnect.",
      href: "/connectors",
    },
    health.tacticalDown.length > 0 && { key: "tactical-down", priority: 1, tone: "bad", text: `Tactical is unreachable from ${health.tacticalDown.map((t) => t.name).join(", ")}`, href: "/connectors" },
    health.tacticalMessagingDown.length > 0 && {
      key: "tactical-messaging-down",
      priority: 1,
      tone: "bad",
      text: `Tactical messaging down at ${health.tacticalMessagingDown.map((t) => t.name).join(", ")} — no PC can be reached`,
      hint: "Deployments wait and retry automatically; the site's watchdog restarts Tactical's message bus.",
      href: "/connectors",
    },
    ...top.slice(0, 2).map((m, i) => ({
      key: `patch-${m.patchId}`,
      priority: m.severity === "CRITICAL" ? 2 : 6,
      tone: m.severity === "CRITICAL" ? ("bad" as const) : ("warn" as const),
      text: `${patchLabel(m)} — missing on ${ofN(m.pcs, n)} PCs — ${SEVERITY_LABEL[m.severity]}`,
      hint: i === 0 && top.length > 2 ? `${plural(top.length - 2, "more patch", "more patches")} missing — see Patches.` : undefined,
      href: `/patches/${m.patchId}`,
    })),
    pending > 0 && {
      key: "pending-approval",
      priority: 3,
      tone: "warn",
      text: `${plural(pending, "change request")} waiting for approval`,
      hint: viewer.canApprove ? "You can approve requests you did not create yourself." : "A bank approver (not the person who created it) must approve.",
      href: "/change-requests?status=pending",
    },
    c.failedLast7d > 0 && { key: "failed", priority: 4, tone: "bad", text: `${plural(c.failedLast7d, "install")} failed or timed out in the last 7 days`, href: "/change-requests?status=finished" },
    c.unassigned > 0 && { key: "unassigned", priority: 5, tone: "warn", text: `${ofN(c.unassigned, n)} PCs are not in a rollout ring — they are never patched`, href: "/endpoints?ring=none" },
    agentRow && c.agent && {
      key: "agent",
      priority: 7,
      tone: "warn",
      text: `${ofN(agentRow.pcs, n)} PCs run an outdated Tactical agent (latest ${c.agent.version})`,
      href: "/endpoints?show=agent",
    },
    c.reboot > 0 && { key: "reboot", priority: 8, tone: "warn", text: `${ofN(c.reboot, n)} PCs are waiting for a restart to finish installing updates`, href: "/endpoints?show=reboot" },
    c.stale > 0 && n > 0 && { key: "stale", priority: 9, tone: "warn", text: `${ofN(c.stale, n)} PCs have not reported in the last 24 h`, href: "/endpoints?show=unscanned" },
    viewer.platformAdmin && c.held > 0 && { key: "held", priority: 10, tone: "warn", text: `${plural(c.held, "downloaded package")} held for a trust decision (platform admins)`, href: "/apps" },
    !siem.configured && { key: "siem", priority: 11, tone: "warn", text: "No SIEM configured — audit export is mandatory in production", href: "/audit" },
    siem.configured && !siem.ok && { key: "siem", priority: 11, tone: "bad", text: "Audit export to the SIEM is behind", href: "/audit" },
  ];
  return pickAttention(items);
}

function journey(c: Counts, totals: ComplianceBuckets): JourneyStep[] {
  const n = totals.total;
  const pcsMissing = totals.needs + totals.critical;
  const requested = (c.crs.DRAFT ?? 0) + (c.crs.PENDING_APPROVAL ?? 0);
  return [
    { key: "scanned", title: "Scanned", value: `${ofN(c.scannedLast24h, n)} PCs`, explanation: "PCs that reported their updates and software in the last 24 h.", href: "/endpoints?show=unscanned" },
    {
      key: "needed",
      title: "Needed",
      value: plural(c.missing.length, "patch", "patches"),
      explanation: `Missing on ${ofN(pcsMissing, n)} PCs. Pick patches to request.`,
      href: "/patches",
    },
    { key: "requested", title: "Requested", value: plural(requested, "request"), explanation: "Drafts and requests waiting for a checker.", href: "/change-requests?status=open" },
    { key: "approved", title: "Approved", value: plural(c.crs.APPROVED ?? 0, "request"), explanation: "Approved by a different person; ready to deploy.", href: "/change-requests?status=approved" },
    {
      key: "installing",
      title: "Installing",
      value: `${plural(c.installing, "PC")}`,
      explanation: `In progress in ${plural(c.installingCrs, "change request")}, inside maintenance windows.`,
      href: "/change-requests?status=deploying",
    },
    { key: "confirmed", title: "Confirmed", value: plural(c.confirmedThisMonth, "install"), explanation: "Installs the PCs' own inventory confirmed this month.", href: "/change-requests?status=finished" },
  ];
}

export async function loadDashboard(tenantId: string, viewer: DashboardViewer, now = new Date()): Promise<DashboardView> {
  const c = await loadCounts(tenantId, viewer, now);
  const fleet = await loadFleetSource(tenantId, now);
  const health = await connectorHealth(tenantId, now);
  const exp = await auditExportStatus(tenantId);
  const siemConfigured = Boolean(env().SIEM_SYSLOG_URL);
  const siem = { configured: siemConfigured, ok: siemConfigured && exp.pending === 0 && exp.minutesSinceExport !== null && exp.minutesSinceExport < 15 };

  const bucketOf = (ringId: string | null): ComplianceBuckets => {
    const r = c.ringRows.find((x) => x.ringId === ringId);
    return r ? { total: r.total, notScanned: r.notScanned, upToDate: r.upToDate, needs: r.needs, critical: r.critical } : EMPTY_BUCKETS;
  };
  const rings: RingSummary[] = c.rings.map((r) => ({ id: r.id, name: r.name, buckets: bucketOf(r.id) }));
  const unassigned = bucketOf(null);
  if (unassigned.total > 0) rings.push({ id: null, name: "Not in a ring", buckets: unassigned });
  const totals = c.ringRows.reduce<ComplianceBuckets>((acc, r) => addBuckets(acc, { total: r.total, notScanned: r.notScanned, upToDate: r.upToDate, needs: r.needs, critical: r.critical }), EMPTY_BUCKETS);

  return {
    totals,
    rings,
    scannedLast24h: c.scannedLast24h,
    topMissing: c.missing.slice(0, 5),
    distinctMissingPatches: c.missing.length,
    criticalPatchesMissing: c.missing.filter((m) => m.severity === "CRITICAL").length,
    attention: attentionItems(c, totals, fleet, health, viewer, siem),
    journey: journey(c, totals),
    fleet,
  };
}
