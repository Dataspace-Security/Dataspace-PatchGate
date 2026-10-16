import "server-only";
import type { Tx } from "@/lib/tenancy/db";
import { compareVersions } from "@/lib/thirdparty/version";
import { overlapMs, type Period } from "./period";
import type { AppRow, ChangeRow, ConnectorRow, EvidenceBlock, ExceptionRow } from "./types";

/**
 * Period activity of ONE bank: third-party app currency, change requests, exceptions, connector uptime and
 * the audit-chain evidence. Runs inside withTenant(bank) — RLS limits every query to that bank.
 */

const MAX_CHANGES = 5_000;

/** Bank-enabled apps: latest VERIFIED version vs what discovery saw installed. */
export async function appVersions(tx: Tx, tenantId: string): Promise<AppRow[]> {
  const enabled = await tx.tenantApp.findMany({
    where: { tenantId },
    select: { app: { select: { id: true, displayName: true, wingetId: true, versions: { where: { verification: "VERIFIED" }, select: { version: true, patch: { select: { id: true } } } } } } },
  });
  if (enabled.length === 0) return [];
  const appIds = enabled.map((e) => e.app.id);
  const discovered = await tx.discoveredApp.findMany({ where: { tenantId, appId: { in: appIds } }, select: { appId: true, versions: true, endpointCount: true } });
  const latest = enabled.map((e) => {
    const sorted = [...e.app.versions].sort((a, b) => compareVersions(b.version, a.version));
    return { app: e.app, top: sorted[0] ?? null };
  });
  const patchIds = latest.flatMap((l) => (l.top?.patch ? [l.top.patch.id] : []));
  const missing = patchIds.length
    ? await tx.endpointPatchState.groupBy({ by: ["patchId"], where: { tenantId, patchId: { in: patchIds }, status: { in: ["NEEDED", "FAILED"] } }, _count: { _all: true } })
    : [];
  const missingBy = new Map(missing.map((m) => [m.patchId, m._count._all]));
  return latest
    .map(({ app, top }) => {
      const d = discovered.filter((x) => x.appId === app.id);
      const versions = [...new Set(d.flatMap((x) => x.versions))].sort((a, b) => compareVersions(b, a));
      return {
        app: app.displayName,
        wingetId: app.wingetId,
        latestVerified: top?.version ?? null,
        installedVersions: versions.slice(0, 20),
        endpointsWithApp: d.reduce((n, x) => n + x.endpointCount, 0),
        endpointsMissingLatest: top?.patch ? (missingBy.get(top.patch.id) ?? 0) : 0,
      };
    })
    .sort((a, b) => a.app.localeCompare(b.app));
}

/** Change requests with any lifecycle step inside the period. */
export async function changesInPeriod(tx: Tx, tenantId: string, period: Period): Promise<ChangeRow[]> {
  const inRange = { gte: period.from, lt: period.to };
  const crs = await tx.changeRequest.findMany({
    where: { tenantId, OR: [{ createdAt: inRange }, { submittedAt: inRange }, { decidedAt: inRange }, { completedAt: inRange }] },
    orderBy: { createdAt: "asc" },
    take: MAX_CHANGES,
    select: {
      id: true,
      title: true,
      ticketRef: true,
      status: true,
      emergency: true,
      emergencyReason: true,
      createdAt: true,
      submittedAt: true,
      decidedAt: true,
      completedAt: true,
      targetCount: true,
      ring: { select: { name: true } },
      createdBy: { select: { upn: true } },
      approvedBy: { select: { upn: true } },
      approvals: { select: { userUpn: true }, orderBy: { createdAt: "asc" } },
    },
  });
  if (crs.length === 0) return [];
  const counts = await tx.deployment.groupBy({ by: ["changeRequestId", "status"], where: { tenantId, changeRequestId: { in: crs.map((c) => c.id) } }, _count: { _all: true } });
  return crs.map((c) => {
    const mine = counts.filter((x) => x.changeRequestId === c.id);
    const sum = (pred: (s: string) => boolean) => mine.filter((x) => pred(x.status)).reduce((n, x) => n + x._count._all, 0);
    const approvers = [...new Set([...c.approvals.map((a) => a.userUpn), ...(c.approvedBy ? [c.approvedBy.upn] : [])])];
    return {
      id: c.id,
      title: c.title,
      ticketRef: c.ticketRef,
      status: c.status,
      emergency: c.emergency,
      emergencyReason: c.emergencyReason,
      ring: c.ring.name,
      maker: c.createdBy.upn,
      approvers,
      createdAt: c.createdAt,
      submittedAt: c.submittedAt,
      decidedAt: c.decidedAt,
      completedAt: c.completedAt,
      targets: c.targetCount,
      succeeded: sum((s) => s === "SUCCEEDED"),
      failed: sum((s) => s === "FAILED" || s === "TIMED_OUT"),
    };
  });
}

/** Exceptions: discovery apps the bank ignores + packages held for a trust decision (shared catalog). */
export async function exceptions(tx: Tx, tenantId: string): Promise<ExceptionRow[]> {
  const [ignored, held, enabled] = await Promise.all([
    tx.discoveredApp.findMany({ where: { tenantId, ignored: true }, orderBy: { endpointCount: "desc" }, take: 500, select: { displayName: true, publisher: true, endpointCount: true, versions: true, updatedAt: true } }),
    tx.appVersion.findMany({ where: { verification: "HELD" }, orderBy: { createdAt: "asc" }, take: 200, select: { appId: true, version: true, holdReason: true, createdAt: true, app: { select: { displayName: true } } } }),
    tx.tenantApp.findMany({ where: { tenantId }, select: { appId: true } }),
  ]);
  const mine = new Set(enabled.map((e) => e.appId));
  return [
    ...ignored.map((d): ExceptionRow => ({ kind: "ignored-app", name: d.displayName, detail: [d.publisher, d.versions.slice(0, 5).join(", ")].filter(Boolean).join(" · "), endpoints: d.endpointCount, since: d.updatedAt })),
    ...held.map((h): ExceptionRow => ({ kind: "held-package", name: `${h.app.displayName} ${h.version}`, detail: `${h.holdReason ?? "held"}${mine.has(h.appId) ? " · enabled for this bank" : ""}`, endpoints: null, since: h.createdAt })),
  ];
}

/** Connector uptime in the period from recorded outages (> 10 min without heartbeat). */
export async function connectorUptime(tx: Tx, tenantId: string, period: Period, now: Date): Promise<ConnectorRow[]> {
  const [connectors, outages] = await Promise.all([
    tx.connector.findMany({ where: { tenantId }, orderBy: { name: "asc" }, select: { id: true, name: true, status: true, enrolledAt: true, lastSeenAt: true } }),
    tx.connectorOutage.findMany({ where: { tenantId, startedAt: { lt: period.to }, OR: [{ endedAt: null }, { endedAt: { gt: period.from } }] }, select: { connectorId: true, startedAt: true, endedAt: true } }),
  ]);
  const end = new Date(Math.min(period.to.getTime(), now.getTime()));
  return connectors
    .filter((c) => c.status === "ACTIVE" || outages.some((o) => o.connectorId === c.id))
    .map((c) => {
      const start = new Date(Math.max(period.from.getTime(), c.enrolledAt.getTime()));
      const window = Math.max(0, end.getTime() - start.getTime());
      const mine = outages.filter((o) => o.connectorId === c.id);
      const down = mine.reduce((ms, o) => ms + overlapMs(o.startedAt, o.endedAt ?? now, start, end), 0);
      return {
        connector: c.name,
        status: c.status,
        lastSeenAt: c.lastSeenAt,
        outages: mine.length,
        downtimeMinutes: Math.round(down / 60_000),
        uptimePct: window > 0 ? Math.round((1 - down / window) * 1000) / 10 : null,
        offlineNow: mine.some((o) => o.endedAt === null),
      };
    });
}

/** Audit-chain evidence for the period: head at period end + the incremental verifier's verdict. */
export async function auditEvidence(tx: Tx, tenantId: string, period: Period): Promise<EvidenceBlock> {
  const [head, eventsInPeriod, anchor, cp] = await Promise.all([
    tx.auditEvent.findFirst({ where: { tenantId, ts: { lt: period.to } }, orderBy: { seq: "desc" }, select: { seq: true, hash: true, ts: true } }),
    tx.auditEvent.count({ where: { tenantId, ts: { gte: period.from, lt: period.to } } }),
    tx.auditAnchor.findFirst({ where: { tenantId, eventCount: { gt: 0 }, exportedAt: { lt: period.to } }, orderBy: { seq: "desc" }, select: { seq: true, exportedAt: true } }),
    tx.auditVerifyCheckpoint.findUnique({ where: { chain: tenantId } }),
  ]);
  return {
    chain: tenantId,
    headSeq: head?.seq.toString() ?? null,
    headHash: head?.hash ?? null,
    headTs: head?.ts ?? null,
    eventsInPeriod,
    lastAnchorSeq: anchor?.seq.toString() ?? null,
    lastAnchorAt: anchor?.exportedAt ?? null,
    verified: cp ? cp.valid : null,
    verifiedAt: cp?.verifiedAt ?? null,
    fullVerifiedAt: cp?.fullVerifiedAt ?? null,
    verifiedThroughSeq: cp ? cp.seq.toString() : null,
    problem: cp?.problem ?? null,
    coversPeriod: !!cp && cp.valid && (!head || cp.seq >= head.seq),
  };
}
