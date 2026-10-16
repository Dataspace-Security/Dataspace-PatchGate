import "server-only";
import { log } from "@/lib/log";
import { withTenant } from "@/lib/tenancy";
import type { AuthedConnector } from "./auth";
import { ConnectorApiError } from "./errors";
import { tacticalPushSchema } from "./protocol";
import { insertActivities, report, TX_TIMEOUT_MS } from "./tactical-activity";
import { auditDrafts, auditGapDraft, guardResetDraft, type ActivityDraft } from "./tactical-activity-rules";

/**
 * POST /api/connector/v1/tactical-events — real-time Tactical guard (protocol §8). The connector pushes, every
 * ~30 s and only when there is something to report, the out-of-band audit-log entries since its cursor and the
 * approvals it reset itself. Ingested at once with the same persistence as the backstop (tactical-activity.ts):
 * TacticalActivity once per item, `tactical.out_of_band_action` on the bank's chain, coalesced TACTICAL_OUT_OF_BAND.
 * Idempotent (dedupe keys): a re-sent batch stores nothing twice. Signed request (auth.ts), bounded body.
 */

export interface TacticalPushReply {
  /** PatchGate's audit cursor for this connector after the push (also feeds the TACTICAL_AUDIT_SYNC backstop). */
  auditCursor: number;
  stored: number;
}

export async function ingestTacticalPush(connector: AuthedConnector, body: unknown, now = new Date()): Promise<TacticalPushReply> {
  const parsed = tacticalPushSchema.safeParse(body);
  if (!parsed.success) throw new ConnectorApiError(400, `invalid tactical-events: ${parsed.error.issues[0]?.message ?? "malformed"}`);
  const push = parsed.data;
  const { tenantId, id: connectorId } = connector;
  return withTenant(
    tenantId,
    async (tx) => {
      // Same lock as TACTICAL_AUDIT_SYNC results: cursor + dedupe stay consistent per connector.
      await tx.$executeRaw`SELECT pg_advisory_xact_lock(4242006, hashtext(${`tactical-audit:${connectorId}`}))`;
      const conn = await tx.connector.findFirst({ where: { id: connectorId, tenantId }, select: { tacticalAuditCursor: true } });
      if (!conn) throw new ConnectorApiError(404, "unknown connector");
      const drafts: ActivityDraft[] = [];
      let cursor = conn.tacticalAuditCursor;
      if (push.audit) {
        const a = push.audit;
        drafts.push(...auditDrafts(a.events, now));
        if (a.reset) drafts.push(auditGapDraft(`reset:push:${a.afterId}:${a.cursor}`, a.afterId, now));
        // A purged Tactical log restarts its ids: the connector's cursor then replaces PatchGate's.
        cursor = a.reset ? a.cursor : Math.max(cursor, a.cursor);
        if (cursor !== conn.tacticalAuditCursor) await tx.connector.updateMany({ where: { id: connectorId, tenantId }, data: { tacticalAuditCursor: cursor } });
      }
      const resets = push.approvalResets ?? [];
      if (resets.length > 0) {
        // Hostname as PatchGate knows the PC (this bank, this connector); the connector's name otherwise.
        const endpoints = await tx.endpoint.findMany({
          where: { tenantId, connectorId, tacticalAgentId: { in: [...new Set(resets.map((r) => r.agentId))] } },
          select: { tacticalAgentId: true, hostname: true },
        });
        const hostOf = new Map(endpoints.map((e) => [e.tacticalAgentId, e.hostname]));
        for (const r of resets) drafts.push(guardResetDraft(r, hostOf.get(r.agentId) ?? r.hostname, now));
      }
      const inserted = await insertActivities(tx, tenantId, connectorId, drafts);
      await report(tx, tenantId, connectorId, inserted, now);
      if (inserted.length > 0) {
        log.warn("tactical.out_of_band", { tenantId, connectorId, via: "push", count: inserted.length, approvalResets: resets.length });
      }
      return { auditCursor: cursor, stored: inserted.length };
    },
    { timeoutMs: TX_TIMEOUT_MS },
  );
}
