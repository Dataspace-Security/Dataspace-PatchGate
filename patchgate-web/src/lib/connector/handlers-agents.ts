import "server-only";
import type { z } from "zod";
import { appendAudit } from "@/lib/audit/service";
import { withTenant } from "@/lib/tenancy";
import { log } from "@/lib/log";
import type { resultSchemas } from "./protocol";
import type { StoredJob } from "./handlers";

/**
 * SYNC_AGENTS → Endpoints. Endpoint identity is (bank, connector, Tactical agent id):
 *  - known agent of this bank → updated and (re)assigned to this connector (an agent that moved sites
 *    follows the connector that now reports it);
 *  - new agent → created for this bank + connector;
 *  - an agent id already registered to ANOTHER bank is never moved or overwritten (RLS hides that row;
 *    the insert is skipped by the unique index) — reported as a conflict;
 *  - agents this connector no longer reports → unassigned (connectorId = null): no more jobs for them.
 */

type SyncResult = z.infer<(typeof resultSchemas)["SYNC_AGENTS"]>;
type AgentInfo = SyncResult["agents"][number];

const CHUNK = 500;
const TX_TIMEOUT_MS = 120_000;
const MAX_IDS_IN_AUDIT = 50;

export interface SyncSummary {
  agents: number;
  created: number;
  updated: number;
  moved: number;
  unassigned: number;
  conflicts: number;
}

const nn = (v: string | null | undefined): string | null => (v === undefined || v === null || v === "" ? null : v);

async function syncChunk(tenantId: string, connectorId: string, agents: readonly AgentInfo[], now: Date) {
  return withTenant(
    tenantId,
    async (tx) => {
      const ids = agents.map((a) => a.agentId);
      const existing = await tx.endpoint.findMany({
        where: { tenantId, tacticalAgentId: { in: ids } },
        select: { tacticalAgentId: true, connectorId: true },
      });
      const known = new Map(existing.map((e) => [e.tacticalAgentId, e.connectorId]));
      const moved = existing.filter((e) => e.connectorId !== null && e.connectorId !== connectorId).map((e) => e.tacticalAgentId);

      const upd = agents.filter((a) => known.has(a.agentId));
      if (upd.length > 0) {
        // One statement per chunk instead of one UPDATE per PC (sites have thousands of agents).
        await tx.$executeRaw`
          UPDATE "Endpoint" AS e
             SET "hostname" = v.hostname,
                 "site" = v.site,
                 "client" = v.client,
                 "osName" = COALESCE(v.os, e."osName"),
                 "agentVersion" = COALESCE(v.version, e."agentVersion"),
                 "goarch" = COALESCE(v.goarch, e."goarch"),
                 "connectorId" = ${connectorId},
                 "lastSeenAt" = ${now},
                 "updatedAt" = ${now}
            FROM unnest(${upd.map((a) => a.agentId)}::text[], ${upd.map((a) => a.hostname)}::text[], ${upd.map((a) => nn(a.site))}::text[],
                        ${upd.map((a) => nn(a.client))}::text[], ${upd.map((a) => nn(a.os))}::text[], ${upd.map((a) => nn(a.version))}::text[],
                        ${upd.map((a) => nn(a.goarch))}::text[])
                 AS v(agent_id, hostname, site, client, os, version, goarch)
           WHERE e."tenantId" = ${tenantId} AND e."tacticalAgentId" = v.agent_id`;
      }

      const fresh = agents.filter((a) => !known.has(a.agentId));
      let created = 0;
      if (fresh.length > 0) {
        const r = await tx.endpoint.createMany({
          data: fresh.map((a) => ({
            tenantId,
            connectorId,
            tacticalAgentId: a.agentId,
            hostname: a.hostname,
            site: nn(a.site),
            client: nn(a.client),
            osName: nn(a.os),
            agentVersion: nn(a.version),
            goarch: nn(a.goarch),
            lastSeenAt: now,
          })),
          skipDuplicates: true, // an id owned by another bank is skipped, never taken over
        });
        created = r.count;
      }
      const conflicts: string[] = [];
      if (created < fresh.length) {
        const mine = new Set(
          (await tx.endpoint.findMany({ where: { tenantId, tacticalAgentId: { in: fresh.map((a) => a.agentId) } }, select: { tacticalAgentId: true } })).map(
            (e) => e.tacticalAgentId,
          ),
        );
        conflicts.push(...fresh.filter((a) => !mine.has(a.agentId)).map((a) => a.agentId));
      }
      return { created, updated: upd.length, moved, conflicts };
    },
    { timeoutMs: TX_TIMEOUT_MS },
  );
}

export async function applySyncAgents(job: StoredJob, result: SyncResult, now: Date): Promise<SyncSummary> {
  const { tenantId, connectorId } = job;
  // De-duplicate defensively (first occurrence wins).
  const seen = new Set<string>();
  const agents = result.agents.filter((a) => (seen.has(a.agentId) ? false : (seen.add(a.agentId), true)));

  let created = 0;
  let updated = 0;
  const moved: string[] = [];
  const conflicts: string[] = [];
  for (let i = 0; i < agents.length; i += CHUNK) {
    const r = await syncChunk(tenantId, connectorId, agents.slice(i, i + CHUNK), now);
    created += r.created;
    updated += r.updated;
    moved.push(...r.moved);
    conflicts.push(...r.conflicts);
  }

  const summary = await withTenant(
    tenantId,
    async (tx) => {
      let unassigned = 0;
      const current = await tx.endpoint.count({ where: { tenantId, connectorId } });
      if (agents.length === 0 && current > 0) {
        // An empty list from a site that had PCs is far more likely a Tactical glitch than a wiped site.
        log.warn("connector.sync.empty_list_ignored", { connectorId, current });
      } else {
        const r = await tx.endpoint.updateMany({
          where: { tenantId, connectorId, tacticalAgentId: { notIn: [...seen] } },
          data: { connectorId: null },
        });
        unassigned = r.count;
      }
      const s: SyncSummary = { agents: agents.length, created, updated, moved: moved.length, unassigned, conflicts: conflicts.length };
      await appendAudit(
        {
          tenantId,
          actor: `connector:${connectorId}`,
          action: "connector.agents_synced",
          entity: "Connector",
          entityId: connectorId,
          payload: {
            jobId: job.id,
            ...s,
            movedAgents: moved.slice(0, MAX_IDS_IN_AUDIT),
            conflictAgents: conflicts.slice(0, MAX_IDS_IN_AUDIT),
          },
        },
        tx,
      );
      return s;
    },
    { timeoutMs: TX_TIMEOUT_MS },
  );
  if (conflicts.length > 0) log.warn("connector.sync.agent_id_conflicts", { connectorId, tenantId, count: conflicts.length });
  return summary;
}
