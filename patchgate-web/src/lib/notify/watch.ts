import "server-only";
import { Prisma } from "@prisma/client";
import { env } from "@/lib/env";
import { log } from "@/lib/log";
import { auditChains, chainName } from "@/lib/audit/service";
import { auditExportStatus } from "@/lib/audit/export";
import { withPlatform, withTenant } from "@/lib/tenancy/db";
import { enqueueNotification } from "./enqueue";

/**
 * Worker step: time-based alert conditions (nothing "happens" when a connector goes silent).
 *  - Connector offline: ACTIVE connector without a heartbeat for > 10 min → open a ConnectorOutage (one per
 *    connector, unique index) + CONNECTOR_OFFLINE; the first heartbeat after it closes the outage + ONLINE.
 *    Outages also feed the connector-uptime figures of compliance reports.
 *  - SIEM export stale (same rule as /api/ready siemExport): pending events and no export for > 15 min →
 *    SIEM_EXPORT_STALE once per episode (NotificationAlert row), cleared silently when exports resume.
 * Each state change and its notification are written in one transaction.
 */

export const OFFLINE_AFTER_MS = 10 * 60_000;
export const SIEM_STALE_MINUTES = 15;

export interface WatchResult {
  offline: number;
  online: number;
  siemStale: number;
}

function isUniqueViolation(err: unknown): boolean {
  return err instanceof Prisma.PrismaClientKnownRequestError && err.code === "P2002";
}

export async function watchConnectors(now = new Date()): Promise<{ offline: number; online: number }> {
  const { connectors, open } = await withPlatform(async (tx) => ({
    connectors: await tx.connector.findMany({ where: { status: "ACTIVE" }, select: { id: true, tenantId: true, lastSeenAt: true, enrolledAt: true } }),
    open: await tx.connectorOutage.findMany({ where: { endedAt: null }, select: { id: true, connectorId: true, tenantId: true, startedAt: true } }),
  }));
  const openBy = new Map(open.map((o) => [o.connectorId, o]));
  const active = new Set(connectors.map((c) => c.id));
  let offline = 0;
  let online = 0;

  for (const c of connectors) {
    const lastHeard = c.lastSeenAt ?? c.enrolledAt;
    const isOffline = now.getTime() - lastHeard.getTime() > OFFLINE_AFTER_MS;
    const outage = openBy.get(c.id);
    try {
      if (isOffline && !outage) {
        await withTenant(c.tenantId, async (tx) => {
          await tx.connectorOutage.create({ data: { tenantId: c.tenantId, connectorId: c.id, startedAt: lastHeard, detectedAt: now } });
          await enqueueNotification(tx, { event: "CONNECTOR_OFFLINE", tenantId: c.tenantId, connectorId: c.id, lastSeenAt: c.lastSeenAt });
        });
        offline++;
      } else if (!isOffline && outage && c.lastSeenAt) {
        const endedAt = c.lastSeenAt;
        const closed = await withTenant(c.tenantId, async (tx) => {
          const { count } = await tx.connectorOutage.updateMany({ where: { id: outage.id, tenantId: c.tenantId, endedAt: null }, data: { endedAt } });
          if (count !== 1) return false;
          const offlineMinutes = Math.max(0, Math.round((endedAt.getTime() - outage.startedAt.getTime()) / 60_000));
          await enqueueNotification(tx, { event: "CONNECTOR_ONLINE", tenantId: c.tenantId, connectorId: c.id, offlineMinutes });
          return true;
        });
        if (closed) online++;
      }
    } catch (err: unknown) {
      if (!isUniqueViolation(err)) log.error("notify.connector_watch_failed", { connectorId: c.id, err });
    }
  }

  // Revoked / deleted connectors: close their open outage without a notification.
  for (const o of open) {
    if (active.has(o.connectorId)) continue;
    await withTenant(o.tenantId, (tx) => tx.connectorOutage.updateMany({ where: { id: o.id, endedAt: null }, data: { endedAt: now } })).catch((err: unknown) =>
      log.error("notify.connector_outage_close_failed", { outageId: o.id, err }),
    );
  }
  return { offline, online };
}

export async function watchSiemExport(): Promise<number> {
  if (!env().SIEM_SYSLOG_URL) return 0; // readiness reports siemExport=null too
  let raised = 0;
  const alerts = new Set((await withPlatform((tx) => tx.notificationAlert.findMany({ where: { key: { startsWith: "siem-stale:" } }, select: { key: true } }))).map((a) => a.key));
  for (const tenantId of await auditChains()) {
    const chain = chainName(tenantId);
    const key = `siem-stale:${chain}`;
    try {
      const s = await auditExportStatus(tenantId);
      const stale = s.pending > 0 && (s.minutesSinceExport === null || s.minutesSinceExport > SIEM_STALE_MINUTES);
      if (stale && !alerts.has(key)) {
        await withPlatform(async (tx) => {
          await tx.notificationAlert.create({ data: { key, tenantId: null } });
          await enqueueNotification(tx, { event: "SIEM_EXPORT_STALE", chain, chainTenantId: tenantId, pending: s.pending, minutesSinceExport: s.minutesSinceExport });
        });
        raised++;
      } else if (!stale && alerts.has(key)) {
        await withPlatform((tx) => tx.notificationAlert.deleteMany({ where: { key } }));
      }
    } catch (err: unknown) {
      if (!isUniqueViolation(err)) log.error("notify.siem_watch_failed", { chain, err });
    }
  }
  return raised;
}

/** Worker step body. */
export async function runNotificationWatch(now = new Date()): Promise<WatchResult> {
  const c = await watchConnectors(now);
  const siemStale = await watchSiemExport();
  return { ...c, siemStale };
}
