import { createHash } from "node:crypto";
import { TACTICAL_SERVICE_USERNAME, type ApprovalReset, type TacticalAuditEvent } from "./protocol";

/** Pure rules of the Tactical seal (tactical-activity.ts): filtering, de-duplication keys, drift, wording. */

export type ActivitySource = "AUDIT_LOG" | "APPROVAL_GUARD" | "APPROVAL_DRIFT" | "AUDIT_RESET";

export interface ActivityDraft {
  source: ActivitySource;
  dedupeKey: string;
  tacticalId: number | null;
  occurredAt: Date;
  actor: string;
  action: string;
  objectType: string;
  agentHostname: string | null;
  agentId: string | null;
  message: string | null;
  ip: string | null;
}

/** Same rule as the connector (defence in depth): the service account's API work is PatchGate's own. */
export function isOutOfBandEvent(e: Pick<TacticalAuditEvent, "actor" | "action">): boolean {
  return e.actor !== TACTICAL_SERVICE_USERNAME || e.action === "login" || e.action === "failed_login";
}

/** Tactical's entry time; an unparsable or future-skewed value falls back to the time PatchGate received it. */
export function parseOccurredAt(ts: string, now: Date): Date {
  const t = Date.parse(ts);
  if (!Number.isFinite(t) || t > now.getTime() + 24 * 3_600_000) return now;
  return new Date(t);
}

/** Tactical id + entry time: a re-numbered log after a Tactical reinstall never collides with old entries. */
export function auditDedupeKey(tacticalId: number, occurredAt: Date): string {
  return `audit:${tacticalId}:${occurredAt.toISOString()}`;
}

/** One drift alert per PC, set of foreign approvals and day (repeated reads of the same drift alert once). */
export function approvalDriftKey(agentId: string, guids: readonly string[], observedAt: Date): string {
  const h = createHash("sha256").update([...guids].map((g) => g.toLowerCase()).sort().join(",")).digest("hex").slice(0, 16);
  return `drift:${agentId}:${h}:${observedAt.toISOString().slice(0, 10)}`;
}

/** Stored activities of Tactical audit entries (service-account work dropped). */
export function auditDrafts(events: readonly TacticalAuditEvent[], now: Date): ActivityDraft[] {
  return events.filter(isOutOfBandEvent).map((e) => {
    const occurredAt = parseOccurredAt(e.ts, now);
    return {
      source: "AUDIT_LOG",
      dedupeKey: auditDedupeKey(e.id, occurredAt),
      tacticalId: e.id,
      occurredAt,
      actor: e.actor,
      action: e.action,
      objectType: e.objectType,
      agentHostname: e.agentHostname,
      agentId: e.agentId,
      message: e.message,
      ip: e.ip,
    };
  });
}

/** Tactical's audit log does not continue after `afterId` (reset, purged, or a backlog too large to read). */
export function auditGapDraft(dedupeKey: string, afterId: number, now: Date): ActivityDraft {
  return {
    source: "AUDIT_RESET",
    dedupeKey,
    tacticalId: null,
    occurredAt: now,
    actor: "unknown",
    action: "audit_log_gap",
    objectType: "auditlog",
    agentHostname: null,
    agentId: null,
    message: `Tactical's audit log does not continue after entry ${afterId} (reset, purged or too large a backlog): entries may be missing`,
    ip: null,
  };
}

/** One guard detection per PC, update and detection time (re-sent pushes are stored once). */
export function guardResetKey(agentId: string, guid: string, detectedAt: Date): string {
  return `guard:${agentId}:${guid.toLowerCase()}:${detectedAt.toISOString()}`;
}

/** An approval the connector's real-time guard found and reset ("approval of KB… on PC… reset automatically at …"). */
export function guardResetDraft(r: ApprovalReset, hostname: string | null, now: Date): ActivityDraft {
  const at = parseOccurredAt(r.detectedAt, now);
  const what = r.kb ?? r.guid;
  const on = hostname ? ` on ${hostname}` : "";
  const title = r.title ? ` ("${r.title}")` : "";
  const message = r.reset
    ? `Approval of ${what}${on} reset automatically at ${at.toISOString().slice(11, 19)} UTC (set outside PatchGate${title})`
    : `Approval of ${what}${on} set outside PatchGate${title} could NOT be reset automatically: ${r.error ?? "unknown error"} (the guard retries every round)`;
  return {
    source: "APPROVAL_GUARD",
    dedupeKey: guardResetKey(r.agentId, r.guid, at),
    tacticalId: null,
    occurredAt: at,
    actor: "unknown (Tactical does not audit approvals)",
    action: "winupdate_approve",
    objectType: "winupdate",
    agentHostname: hostname,
    agentId: r.agentId,
    message: message.slice(0, 1000),
    ip: null,
  };
}

export interface UpdateApproval {
  guid: string;
  kb: string | null;
  action: string;
  installed: boolean;
}

/** Pending approvals on a PC that PatchGate did not set (ownGuids: from its DEPLOY_WINDOWS jobs, lower case). */
export function foreignApprovals<T extends UpdateApproval>(updates: readonly T[], ownGuids: ReadonlySet<string> | undefined): T[] {
  return updates.filter((u) => u.action === "approve" && !u.installed && !(ownGuids?.has(u.guid.toLowerCase()) ?? false));
}

const ACTION_LABEL: Readonly<Record<string, string>> = {
  login: "dashboard login",
  failed_login: "failed dashboard login",
  execute_script: "ran a script",
  execute_command: "ran a command",
  remote_session: "opened a remote session",
  agent_install: "installed an agent",
  bulk_action: "ran a bulk action",
  url_action: "ran a URL action",
  task_run: "ran a task",
  check_run: "ran a check",
  add: "added",
  modify: "changed",
  delete: "deleted",
  winupdate_approve: "approved Windows updates",
  audit_log_gap: "audit log gap",
};

/** Short one-line description for notifications and the UI. */
export function describeActivity(d: Pick<ActivityDraft, "actor" | "action" | "objectType" | "agentHostname" | "message">): string {
  const what = ACTION_LABEL[d.action] ?? d.action;
  const obj = ["add", "modify", "delete"].includes(d.action) ? ` ${d.objectType}` : "";
  const on = d.agentHostname ? ` on ${d.agentHostname}` : "";
  const msg = d.message ? ` — ${d.message}` : "";
  return `${d.actor}: ${what}${obj}${on}${msg}`.slice(0, 400);
}
