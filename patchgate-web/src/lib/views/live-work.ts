import "server-only";
import type { ConnectorJobType } from "@prisma/client";
import type { Tx } from "@/lib/tenancy";

/** Inventory jobs whose results change the Endpoints page (agent list, scans, Windows Update scan). */
export const INVENTORY_JOB_TYPES: readonly ConnectorJobType[] = ["SYNC_AGENTS", "SCAN", "COLLECT", "WU_SCAN"];

/**
 * Is there connector work in flight for this bank (QUEUED / DELIVERED jobs, optionally of some types)?
 * Drives the live-refresh rate of open pages (lib/views/live.ts). One indexed lookup, LIMIT 1.
 */
export async function hasActiveConnectorJobs(tx: Tx, tenantId: string, types?: readonly ConnectorJobType[]): Promise<boolean> {
  const job = await tx.connectorJob.findFirst({
    where: { tenantId, status: { in: ["QUEUED", "DELIVERED"] }, ...(types ? { type: { in: [...types] } } : {}) },
    select: { id: true },
  });
  return job !== null;
}
