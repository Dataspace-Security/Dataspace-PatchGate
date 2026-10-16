/**
 * Notification event catalogue (pure: no I/O). Every event has a severity, a label for the settings UI and
 * rules for who may switch it off:
 *  - critical events are always delivered (no bank / platform toggle, no personal opt-out);
 *  - account-security notices go to the affected user only and are critical as well.
 */

export const NOTIFICATION_EVENTS = [
  "CR_SUBMITTED",
  "CR_APPROVED",
  "CR_REJECTED",
  "RING_STOPPED",
  "CR_FAILED",
  "CR_DEADLINE",
  "CONNECTOR_OFFLINE",
  "CONNECTOR_ONLINE",
  "WU_LOCK_BROKEN",
  "PACKAGE_HELD",
  "AUDIT_CHAIN_BROKEN",
  "SIEM_EXPORT_STALE",
  "TACTICAL_OUT_OF_BAND",
  "APPROVAL_SETTING_CHANGED",
  "ACCOUNT_LOCKED",
  "PASSWORD_RESET",
] as const;

export type NotificationEvent = (typeof NOTIFICATION_EVENTS)[number];
export type Severity = "info" | "warning" | "critical";

export interface EventInfo {
  label: string;
  severity: Severity;
  /** Audience groups the event can reach (settings UI shows bank toggles only for bank events). */
  bank: boolean;
  platform: boolean;
}

export const EVENT_INFO: Readonly<Record<NotificationEvent, EventInfo>> = {
  CR_SUBMITTED: { label: "Change request submitted for approval", severity: "info", bank: true, platform: true },
  CR_APPROVED: { label: "Change request approved", severity: "info", bank: true, platform: true },
  CR_REJECTED: { label: "Change request rejected", severity: "info", bank: true, platform: true },
  RING_STOPPED: { label: "Deployment ring stopped (too many failures)", severity: "warning", bank: true, platform: true },
  CR_FAILED: { label: "Change request finished with failures", severity: "warning", bank: true, platform: true },
  CR_DEADLINE: { label: "Change request deployment deadline reached", severity: "warning", bank: true, platform: true },
  CONNECTOR_OFFLINE: { label: "Site connector offline (> 10 min)", severity: "warning", bank: true, platform: true },
  CONNECTOR_ONLINE: { label: "Site connector back online", severity: "info", bank: true, platform: true },
  WU_LOCK_BROKEN: { label: "Windows Update no longer locked on a PC (could update from Microsoft directly)", severity: "warning", bank: true, platform: true },
  PACKAGE_HELD: { label: "Package held for a trust decision", severity: "warning", bank: false, platform: true },
  AUDIT_CHAIN_BROKEN: { label: "Audit chain verification failed", severity: "critical", bank: false, platform: true },
  SIEM_EXPORT_STALE: { label: "SIEM audit export stale", severity: "critical", bank: false, platform: true },
  TACTICAL_OUT_OF_BAND: { label: "Action in a site's Tactical outside PatchGate", severity: "critical", bank: true, platform: true },
  APPROVAL_SETTING_CHANGED: { label: "Approval switched on / off for a bank", severity: "critical", bank: true, platform: true },
  ACCOUNT_LOCKED: { label: "Your account was locked", severity: "critical", bank: false, platform: false },
  PASSWORD_RESET: { label: "Your password was reset", severity: "critical", bank: false, platform: false },
};

/** Personal account notices: e-mail to the affected user only (never webhooks, never toggled off). */
export const ACCOUNT_EVENTS: ReadonlySet<NotificationEvent> = new Set(["ACCOUNT_LOCKED", "PASSWORD_RESET"]);

export function isNotificationEvent(v: unknown): v is NotificationEvent {
  return typeof v === "string" && (NOTIFICATION_EVENTS as readonly string[]).includes(v);
}

/** Critical events cannot be disabled by a bank / platform setting nor opted out of by a user. */
export function isCritical(event: NotificationEvent): boolean {
  return EVENT_INFO[event].severity === "critical";
}

/** Events a scope's admin can switch on/off (bank: bank events only). */
export function toggleableEvents(scope: "bank" | "platform"): NotificationEvent[] {
  return NOTIFICATION_EVENTS.filter((e) => !isCritical(e) && EVENT_INFO[e][scope]);
}

/** Events a user may opt out of personally. */
export function optOutableEvents(platformUser: boolean): NotificationEvent[] {
  return NOTIFICATION_EVENTS.filter((e) => !isCritical(e) && (platformUser ? EVENT_INFO[e].platform : EVENT_INFO[e].bank));
}
