import { TACTICAL_SERVICE_USERNAME, type JobPayload, type TacticalAuditEvent } from "../protocol.ts";
import type { TacticalClient } from "../tactical/client.ts";
import type { TacticalAuditLog } from "../tactical/types.ts";
import type { JobResultFor } from "./executors.ts";

/**
 * TACTICAL_AUDIT_SYNC (Tactical seal, read-only): read Tactical's audit log and report every entry with
 * id > afterId that PatchGate's service account did not make — dashboard logins (also break-glass),
 * script runs, agent commands, remote sessions, policy / user / settings changes.
 *
 * Tactical 1.5.x has no "id greater than" filter: the log is read newest first (PATCH /logs/audit/, sorted by
 * id) page by page until an entry at or below the cursor is reached. Entries that shift between pages while
 * reading are de-duplicated by id. Events are returned oldest first, at most `limit`; `more` = the next page
 * is waiting (PatchGate queues it at once). PatchGate stores the cursor and de-duplicates (idempotent).
 */

export const AUDIT_PAGE_SIZE = 200;
/** Bound on one job's Tactical reads (100 × 200 = 20,000 entries). */
export const MAX_AUDIT_PAGES = 100;

/** Logins as the service account are always reported: its dashboard login is blocked, so it is a human trying. */
const ALWAYS_REPORTED_ACTIONS = new Set(["login", "failed_login"]);

export function isOutOfBand(log: Pick<TacticalAuditLog, "username" | "action">): boolean {
  return log.username !== TACTICAL_SERVICE_USERNAME || ALWAYS_REPORTED_ACTIONS.has(log.action);
}

const clip = (s: string | null | undefined, max: number): string | null => (typeof s === "string" && s.length > 0 ? s.slice(0, max) : null);

/** PatchGate requires Tactical's agent auto-update OFF (agents upgrade only through PatchGate change requests). */
export function agentAutoUpdateTurnedOn(log: Pick<TacticalAuditLog, "object_type" | "before_value" | "after_value">): boolean {
  if (log.object_type !== "coresettings") return false;
  const flag = (v: unknown): unknown => (v && typeof v === "object" ? (v as Record<string, unknown>).agent_auto_update : undefined);
  return flag(log.after_value) === true && flag(log.before_value) !== true;
}

export function toAuditEvent(log: TacticalAuditLog): TacticalAuditEvent {
  const message = agentAutoUpdateTurnedOn(log)
    ? `AGENT AUTO-UPDATE TURNED ON (PatchGate requires it off; re-run the site installer to re-seal) — ${log.message ?? ""}`
    : log.message;
  return {
    id: log.id,
    ts: log.entry_time.slice(0, 64),
    actor: log.username.slice(0, 255),
    action: log.action.slice(0, 100),
    objectType: log.object_type.slice(0, 100),
    agentHostname: clip(log.agent, 255),
    agentId: clip(log.agent_id, 255),
    message: clip(message, 1000),
    ip: clip(log.ip_address, 64),
  };
}

/** pageSize: rows per Tactical page (the real-time guard reads small pages every ~30 s; the job reads 200). */
export async function tacticalAuditSync(
  tactical: TacticalClient,
  p: JobPayload<"TACTICAL_AUDIT_SYNC">,
  pageSize = AUDIT_PAGE_SIZE,
): Promise<JobResultFor<"TACTICAL_AUDIT_SYNC">> {
  const first = await tactical.auditLogPage(1, pageSize);
  const newest = first.audit_logs.reduce((m, l) => Math.max(m, l.id), 0);
  // Newest id below the cursor: Tactical's log was reset or purged (reinstall, database restore, tampering).
  const reset = p.afterId > 0 && newest < p.afterId;
  const floor = reset ? 0 : p.afterId;

  const seen = new Map<number, TacticalAuditLog>();
  let page = first;
  let pageNo = 1;
  let reachedFloor = false;
  for (;;) {
    for (const l of page.audit_logs) {
      if (l.id > floor) seen.set(l.id, l);
      else reachedFloor = true;
    }
    if (reachedFloor || page.audit_logs.length === 0 || pageNo * pageSize >= page.total || pageNo >= MAX_AUDIT_PAGES) break;
    pageNo++;
    page = await tactical.auditLogPage(pageNo, pageSize);
  }
  const exhausted = reachedFloor || pageNo * pageSize >= page.total || page.audit_logs.length === 0;
  // Older entries above the cursor could not be read in this job (backlog larger than MAX_AUDIT_PAGES pages):
  // reported as a gap, except on the very first sync of a site (afterId 0: older history is not an alarm).
  const gap = !exhausted && floor > 0;

  const examined = [...seen.values()].sort((a, b) => a.id - b.id);
  const relevant = examined.filter(isOutOfBand);
  const highest = examined.length > 0 ? examined[examined.length - 1]!.id : floor;
  if (relevant.length > p.limit) {
    const events = relevant.slice(0, p.limit).map(toAuditEvent);
    return { events, cursor: events[events.length - 1]!.id, more: true, ...(reset || gap ? { reset: true } : {}) };
  }
  return { events: relevant.map(toAuditEvent), cursor: Math.max(highest, reset ? 0 : p.afterId), more: false, ...(reset || gap ? { reset: true } : {}) };
}
