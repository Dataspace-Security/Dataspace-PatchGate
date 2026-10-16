import "server-only";
import { appendAudit } from "@/lib/audit/service";
import { ensurePackageCached } from "@/lib/deploy/connector-cache";
import { withTenant, type Tx } from "@/lib/tenancy";
import { wuScanCab } from "@/lib/winupdate/hooks";
import { requestAgentSync } from "./connector-schedule";

/**
 * Endpoints page actions for CONNECTOR banks (ADMIN only, audited on the bank's chain):
 *  - "Sync agents now": a SYNC_AGENTS job for each active connector right away (de-duplicated).
 *  - "Request scan of all PCs": the same sync first, every known PC marked due (SCAN + COLLECT by the scheduler,
 *    PCs the sync adds are new and therefore due as well) and — for banks whose Windows updates come through
 *    PatchGate — a WU_SCAN request the scheduler fulfils after the sync result is applied, once the verified
 *    Microsoft scan catalog is cached at the site (SYNC_AGENTS → SCAN → WU_SCAN).
 */

export type WuScanState = "requested" | "catalog_pending" | "catalog_missing" | "not_used";

export interface SyncRequestResult {
  connectors: number;
  syncQueued: number;
  message: string;
}

export interface ScanRequestResult extends SyncRequestResult {
  queued: number;
  wuScan: WuScanState;
}

async function activeConnectorsOf(tx: Tx, tenantId: string): Promise<{ id: string; tenantId: string }[]> {
  return tx.connector.findMany({ where: { tenantId, status: "ACTIVE" }, select: { id: true, tenantId: true } });
}

async function queueSyncs(tx: Tx, connectors: readonly { id: string; tenantId: string }[], now: Date): Promise<number> {
  let n = 0;
  for (const c of connectors) if (await requestAgentSync(tx, c, now)) n++;
  return n;
}

export function syncMessage(connectors: number, syncQueued: number): string {
  if (connectors === 0) return "This bank has no active site connector.";
  return syncQueued > 0
    ? "Syncing PCs from Tactical — new PCs appear in a minute or two."
    : "A sync with Tactical is already in progress — new PCs appear in a minute or two.";
}

export async function requestConnectorAgentSync(tenantId: string, actor: string, now = new Date()): Promise<SyncRequestResult> {
  return withTenant(tenantId, async (tx) => {
    const connectors = await activeConnectorsOf(tx, tenantId);
    const syncQueued = await queueSyncs(tx, connectors, now);
    await appendAudit(
      { tenantId, actor, action: "endpoints.sync_requested", entity: "Connector", entityId: "*", payload: { connectors: connectors.length, syncQueued } },
      tx,
    );
    return { connectors: connectors.length, syncQueued, message: syncMessage(connectors.length, syncQueued) };
  });
}

export function scanMessage(r: { connectors: number; wuScan: WuScanState }): string {
  if (r.connectors === 0) return "This bank has no active site connector.";
  const base = "Syncing PCs from Tactical, then scanning — results appear in a few minutes.";
  switch (r.wuScan) {
    case "requested":
      return `${base} The offline Windows Update scan follows the sync.`;
    case "catalog_pending":
      return `${base} Microsoft scan catalog still downloading/verifying — the Windows scan starts automatically when ready.`;
    case "catalog_missing":
      return `${base} No verified Microsoft scan catalog yet (wsusscn2.cab) — the Windows scan starts automatically once it is verified.`;
    case "not_used":
      return base;
  }
}

export async function requestConnectorScan(tenantId: string, actor: string, now = new Date()): Promise<ScanRequestResult> {
  return withTenant(tenantId, async (tx) => {
    const connectors = await activeConnectorsOf(tx, tenantId);
    const syncQueued = await queueSyncs(tx, connectors, now);
    const r = await tx.endpoint.updateMany({ where: { tenantId }, data: { lastScanRequestedAt: null, lastScanAt: null } });
    const source = (await tx.tenant.findUnique({ where: { id: tenantId }, select: { windowsUpdateSource: true } }))?.windowsUpdateSource ?? "PATCHGATE";
    let wuScan: WuScanState = "not_used";
    if (source === "PATCHGATE" && connectors.length > 0) {
      const cab = await wuScanCab(tx);
      if (!cab) {
        wuScan = "catalog_missing";
      } else {
        let allCached = true;
        // Starts the site download of the catalog when needed (de-duplicated per connector + package).
        for (const c of connectors) if ((await ensurePackageCached(tx, c, cab, now)).state !== "cached") allCached = false;
        wuScan = allCached ? "requested" : "catalog_pending";
      }
      // The request waits for the sync result and the cached catalog (connector-schedule.ts scheduleWuScan).
      await tx.connector.updateMany({ where: { tenantId, status: "ACTIVE" }, data: { wuScanRequestedAt: now } });
    }
    await appendAudit(
      {
        tenantId,
        actor,
        action: "endpoints.scan_requested",
        entity: "Endpoint",
        entityId: "*",
        payload: { count: r.count, connectors: connectors.length, syncQueued, wuScan },
      },
      tx,
    );
    const out = { queued: r.count, connectors: connectors.length, syncQueued, wuScan };
    return { ...out, message: scanMessage(out) };
  });
}
