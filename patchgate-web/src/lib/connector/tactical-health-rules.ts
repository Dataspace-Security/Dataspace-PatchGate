/**
 * Tactical health of a bank site (pure: no I/O; unit-tested). The connector reports it in every heartbeat
 * (protocol heartbeat.tacticalHealth: ok | natsdown | unreachable + since), from its own Tactical calls and the
 * site's NATS watchdog (installers/site/tactical/tactical-watchdog.sh). The stored heartbeat is untrusted JSON.
 *
 * Alerting (tactical-health.ts, worker step): unhealthy for more than TACTICAL_UNHEALTHY_AFTER_MS while the
 * connector is online → ONE critical TACTICAL_UNHEALTHY + audit `tactical.unhealthy` per episode (NotificationAlert
 * row "tactical-health:<connectorId>"); back to ok → TACTICAL_RECOVERED + `tactical.recovered`. Short blips the
 * watchdog fixes within the threshold raise nothing.
 */
import { tacticalHealthSchema, type TACTICAL_HEALTH_STATES } from "./protocol";

export const TACTICAL_UNHEALTHY_AFTER_MS = 5 * 60_000;
export const TACTICAL_HEALTH_ALERT_PREFIX = "tactical-health:";

export type TacticalHealthState = (typeof TACTICAL_HEALTH_STATES)[number];

export interface TacticalHealthView {
  state: TacticalHealthState;
  /** When the current state began (null = not reported: older connector). */
  since: Date | null;
  detail: string | null;
  /** Restarts of trmm-nats by the site watchdog in the last hour (null = no fresh watchdog report). */
  watchdogRestarts: number | null;
  /** false = derived from tactical.reachable only (connector without tacticalHealth). */
  reported: boolean;
}

export function tacticalHealthAlertKey(connectorId: string): string {
  return `${TACTICAL_HEALTH_ALERT_PREFIX}${connectorId}`;
}

function obj(v: unknown): Record<string, unknown> | null {
  return v !== null && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}

function date(v: string | null | undefined): Date | null {
  if (!v) return null;
  const t = Date.parse(v);
  return Number.isFinite(t) ? new Date(t) : null;
}

/** Health from a stored heartbeat (null = no heartbeat / nothing usable). */
export function tacticalHealthView(rawHeartbeat: unknown): TacticalHealthView | null {
  const hb = obj(rawHeartbeat);
  if (!hb) return null;
  const parsed = tacticalHealthSchema.safeParse(hb.tacticalHealth);
  if (parsed.success) {
    const h = parsed.data;
    return { state: h.state, since: date(h.since), detail: h.detail ?? null, watchdogRestarts: h.watchdog?.restartsLastHour ?? null, reported: true };
  }
  const reachable = obj(hb.tactical)?.reachable;
  if (typeof reachable !== "boolean") return null;
  return { state: reachable ? "ok" : "unreachable", since: null, detail: null, watchdogRestarts: null, reported: false };
}

/** Milliseconds the site has been unhealthy (0 = healthy or unknown start; a future "since" counts as now). */
export function unhealthyForMs(view: TacticalHealthView | null, now: Date): number {
  if (!view || view.state === "ok" || !view.since) return 0;
  return Math.max(0, now.getTime() - view.since.getTime());
}

export type TacticalAlertDecision = "raise" | "recover" | "none";

/**
 * One decision per connector and watch run. While the connector itself is offline nothing changes (the
 * CONNECTOR_OFFLINE alert covers it; an open Tactical alert stays open until a heartbeat says ok again).
 */
export function decideTacticalAlert(input: { view: TacticalHealthView | null; online: boolean; alertOpen: boolean; now: Date }): TacticalAlertDecision {
  const { view, online, alertOpen, now } = input;
  if (!online || !view) return "none";
  if (view.state === "ok") return alertOpen ? "recover" : "none";
  // Older connectors report no "since": their Tactical outage cannot be timed, so it is shown but not alerted.
  if (!alertOpen && view.reported && unhealthyForMs(view, now) > TACTICAL_UNHEALTHY_AFTER_MS) return "raise";
  return "none";
}

/** Plain-words label for the UI. */
export function tacticalHealthLabel(state: TacticalHealthState): string {
  return state === "ok" ? "healthy" : state === "natsdown" ? "messaging down" : "unreachable";
}
