import "server-only";
import type { z } from "zod";
import { appendAudit } from "@/lib/audit/service";
import type { SessionUser } from "@/lib/auth/session";
import { DomainError } from "@/lib/errors";
import { log } from "@/lib/log";
import { enqueueNotification } from "@/lib/notify/enqueue";
import { canActForTenant, isValidTenantId, withPlatform, withTenant, type Tx } from "@/lib/tenancy";
import { enqueueTacticalAudit } from "@/lib/scan/connector-schedule";
import { enqueueJob } from "./queue";
import type { StoredJob } from "./handlers";
import type { resultSchemas } from "./protocol";
import { approvalDriftKey, auditDrafts, auditGapDraft, describeActivity, foreignApprovals, type ActivityDraft } from "./tactical-activity-rules";

/**
 * Tactical seal — PatchGate side (RUNBOOK "Tactical is sealed").
 *
 *  - Real time (connector protocol §8, tactical-push.ts): the connector's guard reads Tactical's audit log and
 *    update approvals every ~30 s, resets approvals PatchGate did not authorise itself and pushes both.
 *  - Backstop: TACTICAL_AUDIT_SYNC results (catch-up from PatchGate's cursor) and the COLLECT comparison below.
 *  - Every out-of-band item is stored once (TacticalActivity, unique per connector + dedupe key), audited as
 *    `tactical.out_of_band_action` on the BANK's chain (→ the bank SIEM through the audit relay) and notified
 *    (critical event TACTICAL_OUT_OF_BAND: platform admins + the bank's admins), bursts coalesced.
 *  - Approval drift (backstop): Tactical 1.5.x does NOT audit update approvals ("approve" on an agent's Patches
 *    tab, "Install Approved Updates"). Every COLLECT page is compared with the approvals PatchGate itself set
 *    (DEPLOY_WINDOWS jobs); a foreign approval the guard did not already undo is recorded, alerted and — when
 *    PatchGate has no deployment in flight on that PC — undone with RESET_APPROVALS.
 */

type AuditResult = z.infer<(typeof resultSchemas)["TACTICAL_AUDIT_SYNC"]>;
type CollectResult = z.infer<(typeof resultSchemas)["COLLECT"]>;

/** PatchGate's own DEPLOY_WINDOWS approvals are recognised for this long after the job expired. */
export const OWN_APPROVAL_MEMORY_MS = 7 * 24 * 60 * 60_000;
const RESET_TTL_MS = 60 * 60_000;
export const TX_TIMEOUT_MS = 120_000;
/**
 * One incident, one alert: TACTICAL_OUT_OF_BAND is sent at most once per bank in this window. Later activity is
 * still stored, audited and listed at once, and counted in the next alert after the window.
 */
export const NOTIFY_COALESCE_MS = 5 * 60_000;

interface Inserted {
  id: string;
  draft: ActivityDraft;
}

export async function insertActivities(tx: Tx, tenantId: string, connectorId: string, drafts: readonly ActivityDraft[]): Promise<Inserted[]> {
  if (drafts.length === 0) return [];
  const rows = await tx.tacticalActivity.createManyAndReturn({
    data: drafts.map((d) => ({ tenantId, connectorId, ...d })),
    skipDuplicates: true, // re-delivered / overlapping pages: each entry is stored (and alerted) once
    select: { id: true, dedupeKey: true },
  });
  const byKey = new Map(drafts.map((d) => [d.dedupeKey, d]));
  return rows.map((r) => ({ id: r.id, draft: byKey.get(r.dedupeKey)! }));
}

/** Audit each new activity on the bank's chain, mark human activity and send ONE (coalesced) notification. */
export async function report(tx: Tx, tenantId: string, connectorId: string, inserted: readonly Inserted[], now: Date): Promise<void> {
  if (inserted.length === 0) return;
  await tx.connector.updateMany({ where: { id: connectorId, tenantId }, data: { tacticalHumanSeenAt: now } });
  for (const { id, draft: d } of inserted) {
    await appendAudit(
      {
        tenantId,
        actor: `tactical:${d.actor}`.slice(0, 300),
        action: "tactical.out_of_band_action",
        entity: "Connector",
        entityId: connectorId,
        payload: {
          activityId: id,
          source: d.source,
          tacticalId: d.tacticalId,
          occurredAt: d.occurredAt.toISOString(),
          tacticalUser: d.actor,
          tacticalAction: d.action,
          objectType: d.objectType,
          agentHostname: d.agentHostname,
          agentId: d.agentId,
          message: d.message,
          ip: d.ip,
        },
      },
      tx,
    );
  }
  const last = await tx.notification.findFirst({ where: { tenantId, event: "TACTICAL_OUT_OF_BAND" }, orderBy: { createdAt: "desc" }, select: { createdAt: true } });
  if (last && now.getTime() - last.createdAt.getTime() < NOTIFY_COALESCE_MS) {
    log.info("tactical.out_of_band.coalesced", { tenantId, connectorId, count: inserted.length });
    return;
  }
  // Activity coalesced into the previous alert's window is counted in this one.
  const since = last ? await tx.tacticalActivity.count({ where: { tenantId, connectorId, receivedAt: { gt: last.createdAt } } }) : 0;
  const latest = inserted[inserted.length - 1]!.draft;
  await enqueueNotification(tx, { event: "TACTICAL_OUT_OF_BAND", tenantId, connectorId, count: Math.max(inserted.length, since), summary: describeActivity(latest) });
}

export async function applyTacticalAudit(job: StoredJob, result: AuditResult, now: Date): Promise<{ stored: number; cursor: number }> {
  const { tenantId, connectorId } = job;
  return withTenant(
    tenantId,
    async (tx) => {
      // Results of one connector are applied one at a time (cursor + dedupe stay consistent).
      await tx.$executeRaw`SELECT pg_advisory_xact_lock(4242006, hashtext(${`tactical-audit:${connectorId}`}))`;
      const conn = await tx.connector.findFirst({ where: { id: connectorId, tenantId }, select: { tacticalAuditCursor: true } });
      if (!conn) return { stored: 0, cursor: 0 };
      const drafts: ActivityDraft[] = auditDrafts(result.events, now);
      if (result.reset) drafts.push(auditGapDraft(`reset:${job.id}`, conn.tacticalAuditCursor, now));
      const cursor = result.reset ? result.cursor : Math.max(conn.tacticalAuditCursor, result.cursor);
      await tx.connector.updateMany({ where: { id: connectorId, tenantId }, data: { tacticalAuditCursor: cursor } });
      // Sign the follow-up job before the audit chain lock is taken (queue.ts: no long locks before signing).
      if (result.more) await enqueueTacticalAudit(tx, { id: connectorId, tenantId }, cursor, now);
      const inserted = await insertActivities(tx, tenantId, connectorId, drafts);
      await report(tx, tenantId, connectorId, inserted, now);
      if (inserted.length > 0) log.warn("tactical.out_of_band", { tenantId, connectorId, jobId: job.id, count: inserted.length });
      return { stored: inserted.length, cursor };
    },
    { timeoutMs: TX_TIMEOUT_MS },
  );
}

interface DeployJobRow {
  payload: unknown;
  status: string;
  expiresAt: Date;
}

/** Approvals PatchGate set itself (DEPLOY_WINDOWS) per agent, and agents with a deployment still in flight. */
function ownApprovals(jobs: readonly DeployJobRow[], now: Date): { guids: Map<string, Set<string>>; active: Set<string> } {
  const guids = new Map<string, Set<string>>();
  const active = new Set<string>();
  for (const j of jobs) {
    const p = j.payload as { agentId?: unknown; guids?: unknown };
    if (typeof p?.agentId !== "string" || !Array.isArray(p.guids)) continue;
    const set = guids.get(p.agentId) ?? new Set<string>();
    for (const g of p.guids) if (typeof g === "string") set.add(g.toLowerCase());
    guids.set(p.agentId, set);
    if (j.status === "QUEUED" || j.status === "DELIVERED" || j.expiresAt > now) active.add(p.agentId);
  }
  return { guids, active };
}

/**
 * Approval drift — backstop of the connector's real-time guard (called after a COLLECT page was ingested).
 * Returns the number of new drift activities. A reset is queued for every drifting PC without a PatchGate
 * deployment in flight (no outstanding reset yet).
 */
export async function checkApprovalDrift(job: StoredJob, result: CollectResult, observedAt: Date, now: Date): Promise<number> {
  const candidates = result.agents.filter((a) => !a.error && a.updates?.some((u) => u.action === "approve" && !u.installed));
  if (candidates.length === 0) return 0;
  const { tenantId, connectorId } = job;
  return withTenant(
    tenantId,
    async (tx) => {
      const agentIds = candidates.map((a) => a.agentId);
      const endpoints = await tx.endpoint.findMany({ where: { tenantId, connectorId, tacticalAgentId: { in: agentIds } }, select: { tacticalAgentId: true, hostname: true } });
      const hostOf = new Map(endpoints.map((e) => [e.tacticalAgentId, e.hostname]));
      const deployJobs = await tx.connectorJob.findMany({
        where: { tenantId, connectorId, type: "DEPLOY_WINDOWS", status: { not: "CANCELLED" }, expiresAt: { gt: new Date(now.getTime() - OWN_APPROVAL_MEMORY_MS) } },
        select: { payload: true, status: true, expiresAt: true },
      });
      const own = ownApprovals(deployJobs, now);
      const pendingResets = await tx.connectorJob.findMany({
        where: { tenantId, connectorId, type: "RESET_APPROVALS", status: { in: ["QUEUED", "DELIVERED"] } },
        select: { payload: true },
      });
      const resetting = new Set(pendingResets.map((r) => (r.payload as { agentId?: string }).agentId));

      const drafts: ActivityDraft[] = [];
      for (const a of candidates) {
        if (!hostOf.has(a.agentId)) continue; // not this bank's PC on this connector
        const foreign = foreignApprovals(a.updates ?? [], own.guids.get(a.agentId));
        if (foreign.length === 0) continue;
        const reset = !own.active.has(a.agentId) && !resetting.has(a.agentId);
        if (reset) {
          await enqueueJob(tx, { tenantId, connectorId, type: "RESET_APPROVALS", payload: { agentId: a.agentId }, expiresAt: new Date(now.getTime() + RESET_TTL_MS) }, now);
          resetting.add(a.agentId);
        }
        const kbs = foreign.map((u) => u.kb ?? u.guid).slice(0, 10).join(", ");
        drafts.push({
          source: "APPROVAL_DRIFT",
          dedupeKey: approvalDriftKey(a.agentId, foreign.map((u) => u.guid), observedAt),
          tacticalId: null,
          occurredAt: observedAt,
          actor: "unknown (Tactical does not audit approvals)",
          action: "winupdate_approve",
          objectType: "winupdate",
          agentHostname: hostOf.get(a.agentId) ?? null,
          agentId: a.agentId,
          message: `${foreign.length} update approval(s) set outside PatchGate: ${kbs}${reset ? " (approvals reset by PatchGate)" : " (PatchGate deployment in flight: not reset)"}`.slice(0, 1000),
          ip: null,
        });
      }
      const inserted = await insertActivities(tx, tenantId, connectorId, drafts);
      await report(tx, tenantId, connectorId, inserted, now);
      if (drafts.length > 0) log.warn("tactical.approval_drift", { tenantId, connectorId, jobId: job.id, agents: drafts.length, new: inserted.length });
      return inserted.length;
    },
    { timeoutMs: TX_TIMEOUT_MS },
  );
}

// ---------------------------------------------------------------------------------------------------------
// Read + acknowledge (Connectors page)
// ---------------------------------------------------------------------------------------------------------

export interface TacticalActivityView {
  id: string;
  tenantId: string;
  tenantName: string;
  connectorName: string;
  source: string;
  occurredAt: Date;
  actor: string;
  action: string;
  objectType: string;
  agentHostname: string | null;
  message: string | null;
  ip: string | null;
  acknowledgedAt: Date | null;
  acknowledgedBy: string | null;
}

export interface TacticalActivityList {
  rows: TacticalActivityView[];
  unacknowledged: number;
}

const LIST_LIMIT = 100;

/** Platform users: every bank. Bank users (ADMIN / AUDITOR): their own bank. */
export async function listTacticalActivity(scope: { kind: "platform" } | { kind: "tenant"; tenantId: string }): Promise<TacticalActivityList> {
  const run = async (tx: Tx) => {
    const where = scope.kind === "tenant" ? { tenantId: scope.tenantId } : {};
    const [rows, unacknowledged, connectors, tenants] = await Promise.all([
      tx.tacticalActivity.findMany({ where, orderBy: [{ acknowledgedAt: { sort: "desc", nulls: "first" } }, { occurredAt: "desc" }], take: LIST_LIMIT }),
      tx.tacticalActivity.count({ where: { ...where, acknowledgedAt: null } }),
      tx.connector.findMany({ where, select: { id: true, name: true } }),
      tx.tenant.findMany({ where: scope.kind === "tenant" ? { id: scope.tenantId } : {}, select: { id: true, name: true } }),
    ]);
    const cName = new Map(connectors.map((c) => [c.id, c.name]));
    const tName = new Map(tenants.map((t) => [t.id, t.name]));
    return {
      unacknowledged,
      rows: rows.map((r) => ({
        id: r.id,
        tenantId: r.tenantId,
        tenantName: tName.get(r.tenantId) ?? r.tenantId,
        connectorName: cName.get(r.connectorId) ?? r.connectorId,
        source: r.source,
        occurredAt: r.occurredAt,
        actor: r.actor,
        action: r.action,
        objectType: r.objectType,
        agentHostname: r.agentHostname,
        message: r.message,
        ip: r.ip,
        acknowledgedAt: r.acknowledgedAt,
        acknowledgedBy: r.acknowledgedBy,
      })),
    };
  };
  return scope.kind === "tenant" ? withTenant(scope.tenantId, run) : withPlatform(run);
}

/**
 * ADMIN (bank admin of that bank, or platform admin): acknowledge activities of one bank — all open ones, or
 * the given ids. Audited on the bank's chain. Returns how many were acknowledged.
 */
export async function acknowledgeTacticalActivity(user: SessionUser, tenantId: string, ids: readonly string[] | null, note: string | null): Promise<number> {
  if (!isValidTenantId(tenantId) || !canActForTenant(user, tenantId)) throw new DomainError("Bank not found", 404);
  return withTenant(tenantId, async (tx) => {
    const now = new Date();
    const where = { tenantId, acknowledgedAt: null, ...(ids ? { id: { in: [...ids] } } : {}) };
    const open = await tx.tacticalActivity.findMany({ where, select: { id: true }, take: 1000 });
    if (open.length === 0) return 0;
    await tx.tacticalActivity.updateMany({ where: { id: { in: open.map((o) => o.id) }, tenantId }, data: { acknowledgedAt: now, acknowledgedBy: user.upn } });
    await appendAudit(
      {
        tenantId,
        actor: user.upn,
        action: "tactical.activity_acknowledged",
        entity: "TacticalActivity",
        entityId: open.length === 1 ? open[0]!.id : "*",
        payload: { count: open.length, ids: open.slice(0, 50).map((o) => o.id), note },
      },
      tx,
    );
    return open.length;
  });
}
