import "server-only";
import type { z } from "zod";
import { withTenant } from "@/lib/tenancy";
import { log } from "@/lib/log";
import { writeEndpointSnapshot } from "@/lib/scan/ingest";
import { RESCAN_INTERVAL_MS, RETRY_UNREACHABLE_MS } from "@/lib/scan/connector-schedule";
import { confirmSentDeployments } from "@/lib/deploy/connector-confirm";
import type { resultSchemas } from "./protocol";
import type { StoredJob } from "./handlers";

/**
 * SCAN / COLLECT results → the same tables the direct Tactical path writes (scan/ingest.ts), so
 * compliance, discovery and deployment confirmation work identically for connector-backed banks.
 * Only endpoints of THIS bank currently assigned to THIS connector are written (a stale page from a
 * site an agent has moved away from is ignored).
 */

type ScanResult = z.infer<(typeof resultSchemas)["SCAN"]>;
type CollectResult = z.infer<(typeof resultSchemas)["COLLECT"]>;

/** One endpoint's write-back can be hundreds of upserts. */
const INGEST_TX_TIMEOUT_MS = 60_000;

async function endpointsByAgent(tenantId: string, connectorId: string, agentIds: readonly string[]): Promise<Map<string, string>> {
  const rows = await withTenant(tenantId, (tx) =>
    tx.endpoint.findMany({ where: { tenantId, connectorId, tacticalAgentId: { in: [...agentIds] } }, select: { id: true, tacticalAgentId: true } }),
  );
  return new Map(rows.map((r) => [r.tacticalAgentId, r.id]));
}

export async function applyScan(job: StoredJob, result: ScanResult, now: Date): Promise<void> {
  const { tenantId, connectorId } = job;
  const failedIds = result.failed.map((f) => f.agentId);
  await withTenant(tenantId, async (tx) => {
    if (result.requested.length > 0) {
      await tx.endpoint.updateMany({ where: { tenantId, connectorId, tacticalAgentId: { in: result.requested } }, data: { lastScanRequestedAt: now } });
    }
    if (failedIds.length > 0) {
      // Unreachable PCs are asked again in about an hour instead of tomorrow.
      await tx.endpoint.updateMany({
        where: { tenantId, connectorId, tacticalAgentId: { in: failedIds } },
        data: { lastScanRequestedAt: new Date(now.getTime() - RESCAN_INTERVAL_MS + RETRY_UNREACHABLE_MS) },
      });
    }
  });
  if (failedIds.length > 0) log.info("connector.scan.partial", { jobId: job.id, tenantId: job.tenantId, failed: failedIds.length });
}

export interface CollectSummary {
  ingested: number;
  failed: number;
  unknown: number;
  software: boolean;
}

export async function applyCollect(job: StoredJob, result: CollectResult, now: Date): Promise<CollectSummary> {
  const { tenantId, connectorId } = job;
  // When the data was read on the site (the connector picked the job up then) — what "fresh" means when
  // confirming installs: a page read before an install started never confirms it.
  const observedAt = job.deliveredAt && job.deliveredAt <= now ? job.deliveredAt : now;
  const byAgent = await endpointsByAgent(tenantId, connectorId, result.agents.map((a) => a.agentId));
  const ingestedIds: string[] = [];
  let failed = 0;
  let unknown = 0;
  let software = false;
  for (const a of result.agents) {
    const endpointId = byAgent.get(a.agentId);
    if (!endpointId) {
      unknown++;
      continue;
    }
    if (a.error) {
      failed++;
      continue; // ingestAttemptAt (set when the batch was scheduled) moves it to the back of the queue
    }
    software ||= a.software !== undefined;
    await withTenant(
      tenantId,
      (tx) =>
        writeEndpointSnapshot(
          tx,
          tenantId,
          endpointId,
          {
            updates: a.updates,
            inventory: a.software?.map((s) => ({ name: s.name, version: s.version, publisher: s.publisher ?? null, uninstall: s.uninstall ?? null })),
            agent: a.agent ? { version: a.agent.version, goarch: a.agent.goarch ?? null } : undefined,
          },
          observedAt,
        ),
      { timeoutMs: INGEST_TX_TIMEOUT_MS },
    );
    ingestedIds.push(endpointId);
  }
  if (unknown > 0) log.info("connector.collect.unknown_agents", { jobId: job.id, tenantId: job.tenantId, unknown });
  // Fresh data may confirm installs that were waiting for it.
  if (ingestedIds.length > 0) await confirmSentDeployments(tenantId, now, ingestedIds);
  return { ingested: ingestedIds.length, failed, unknown, software };
}
