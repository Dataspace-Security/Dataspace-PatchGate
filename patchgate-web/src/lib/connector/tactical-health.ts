import "server-only";
import { Prisma } from "@prisma/client";
import { appendAudit } from "@/lib/audit/service";
import { log } from "@/lib/log";
import { enqueueNotification } from "@/lib/notify/enqueue";
import { withPlatform, withTenant, type Tx } from "@/lib/tenancy/db";
import { isOnline } from "./policy";
import { TACTICAL_HEALTH_ALERT_PREFIX, decideTacticalAlert, tacticalHealthAlertKey, tacticalHealthView } from "./tactical-health-rules";

/**
 * Worker step (runs with the notification watch): turns the Tactical health the connectors report into one
 * critical alert per episode (rules: tactical-health-rules.ts). Each state change, its audit event on the
 * bank's chain and its notification are written in ONE tenant-scoped transaction; the NotificationAlert row
 * (unique key per connector) coalesces repeated runs and concurrent workers into a single alert.
 */

export interface TacticalHealthWatchResult {
  raised: number;
  recovered: number;
}

function isUniqueViolation(err: unknown): boolean {
  return err instanceof Prisma.PrismaClientKnownRequestError && err.code === "P2002";
}

export async function watchTacticalHealth(now = new Date()): Promise<TacticalHealthWatchResult> {
  const { connectors, alerts } = await withPlatform(async (tx) => ({
    connectors: await tx.connector.findMany({ where: { status: "ACTIVE" }, select: { id: true, tenantId: true, lastSeenAt: true, heartbeat: true } }),
    alerts: await tx.notificationAlert.findMany({ where: { key: { startsWith: TACTICAL_HEALTH_ALERT_PREFIX } }, select: { key: true, tenantId: true, raisedAt: true } }),
  }));
  const open = new Map(alerts.map((a) => [a.key, a]));
  const active = new Set<string>();
  let raised = 0;
  let recovered = 0;

  for (const c of connectors) {
    const key = tacticalHealthAlertKey(c.id);
    active.add(key);
    const view = tacticalHealthView(c.heartbeat);
    const alert = open.get(key);
    const decision = decideTacticalAlert({ view, online: isOnline(c.lastSeenAt, now), alertOpen: alert !== undefined, now });
    try {
      if (decision === "raise" && view) {
        await withTenant(c.tenantId, async (tx) => {
          await tx.notificationAlert.create({ data: { key, tenantId: c.tenantId, raisedAt: now } });
          await appendAudit(
            {
              tenantId: c.tenantId,
              actor: "system",
              action: "tactical.unhealthy",
              entity: "Connector",
              entityId: c.id,
              payload: { state: view.state, since: view.since?.toISOString() ?? null, detail: view.detail, watchdogRestartsLastHour: view.watchdogRestarts },
            },
            tx,
          );
          await enqueueNotification(tx, {
            event: "TACTICAL_UNHEALTHY",
            tenantId: c.tenantId,
            connectorId: c.id,
            state: view.state,
            since: view.since,
            detail: view.detail,
            watchdogRestarts: view.watchdogRestarts,
          });
        });
        raised++;
      } else if (decision === "recover" && alert) {
        const done = await withTenant(c.tenantId, async (tx) => {
          const { count } = await tx.notificationAlert.deleteMany({ where: { key, tenantId: c.tenantId } });
          if (count !== 1) return false; // another worker recovered it first
          const minutes = Math.max(0, Math.round((now.getTime() - alert.raisedAt.getTime()) / 60_000));
          await appendAudit(
            { tenantId: c.tenantId, actor: "system", action: "tactical.recovered", entity: "Connector", entityId: c.id, payload: { alertedAt: alert.raisedAt.toISOString(), alertedMinutes: minutes } },
            tx,
          );
          await enqueueNotification(tx, { event: "TACTICAL_RECOVERED", tenantId: c.tenantId, connectorId: c.id, unhealthyMinutes: minutes });
          return true;
        });
        if (done) recovered++;
      }
    } catch (err: unknown) {
      if (!isUniqueViolation(err)) log.error("notify.tactical_health_watch_failed", { connectorId: c.id, err });
    }
  }

  // Revoked / deleted connectors: drop their open alert without a notification.
  for (const a of alerts) {
    if (active.has(a.key)) continue;
    const drop = (tx: Tx) => tx.notificationAlert.deleteMany({ where: { key: a.key } });
    await (a.tenantId ? withTenant(a.tenantId, drop) : withPlatform(drop)).catch((err: unknown) => log.error("notify.tactical_health_alert_drop_failed", { key: a.key, err }));
  }
  return { raised, recovered };
}
