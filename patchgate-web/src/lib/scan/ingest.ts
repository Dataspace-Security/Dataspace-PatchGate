import "server-only";
import type { TacticalClient } from "@/lib/tactical/client";
import type { SoftwareItem } from "@/lib/tactical/types";
import { legacyTacticalTenantId } from "@/lib/tactical/from-env";
import { tenantUsesConnector } from "@/lib/connector/routing";
import { log } from "@/lib/log";
import { compareVersions } from "@/lib/thirdparty/version";
import { withTenant, type Tx } from "@/lib/tenancy";
import { mapSeverity, thirdPartyStatus } from "./map";
import { normGuid } from "@/lib/tactical/deploy-plan";
import { rebuildDiscovered, recordInventory } from "@/lib/discovery/service";

/**
 * Windows Update + software inventory -> EndpointPatchState / InstalledSoftware, so the dashboard shows
 * real compliance. Two sources feed the same writer (writeEndpointSnapshot):
 *  - the connector pipeline: COLLECT results (src/lib/connector/handlers-inventory.ts), any bank;
 *  - the direct Tactical path below: ONE bank (LEGACY_TACTICAL_TENANT_ID) while it has no connector.
 *    Tactical is read first, then everything is written in one transaction scoped to that bank.
 * Tactical's own scan schedule is disabled, so PatchGate asks agents to rescan periodically.
 */

const READ_INTERVAL_MS = 6 * 60 * 60_000;
const SCAN_REQUEST_INTERVAL_MS = 24 * 60 * 60_000;
const BATCH = 20;
/** Unreachable PCs are retried after this, so they never starve the rest of the fleet. */
const RETRY_FAILED_MS = 60 * 60_000;
/** One endpoint's write-back can be hundreds of upserts. */
const INGEST_TX_TIMEOUT_MS = 60_000;

interface CurrentRelease {
  patchId: string;
  inventoryMatch: string;
  version: string;
}

/** Newest verified, out-of-quarantine version per app THIS bank has enabled (the compliance target). */
async function currentThirdPartyReleases(tx: Tx, tenantId: string, now: Date): Promise<CurrentRelease[]> {
  const versions = await tx.appVersion.findMany({
    where: {
      verification: "VERIFIED",
      availableAt: { lte: now },
      patch: { isNot: null },
      app: { tenants: { some: { tenantId } } },
    },
    include: { app: true, patch: { select: { id: true } } },
  });
  const best = new Map<string, (typeof versions)[number]>();
  for (const v of versions) {
    const cur = best.get(v.appId);
    if (!cur || compareVersions(v.version, cur.version) > 0) best.set(v.appId, v);
  }
  return [...best.values()].flatMap((v) =>
    v.patch ? [{ patchId: v.patch.id, inventoryMatch: v.app.inventoryMatch, version: v.version }] : [],
  );
}

/** One Windows update as Tactical reports it (directly, or relayed in a COLLECT result). */
export interface UpdateRow {
  id: number;
  guid: string;
  kb: string | null;
  title: string | null;
  installed: boolean;
  severity: string | null;
}

/** What is known about one PC now. Parts that were not collected are left untouched. */
export interface EndpointSnapshot {
  updates?: readonly UpdateRow[];
  inventory?: readonly SoftwareItem[];
  agent?: { version: string; goarch?: string | null };
}

/** Write one endpoint's snapshot (inside withTenant(tenantId)). */
export async function writeEndpointSnapshot(
  tx: Tx,
  tenantId: string,
  endpointId: string,
  snap: EndpointSnapshot,
  now: Date,
): Promise<{ windows: number; thirdParty: number }> {
  const windows = snap.updates ? await writeWindowsUpdates(tx, tenantId, endpointId, snap.updates) : 0;
  const thirdParty = snap.inventory ? await writeInventory(tx, tenantId, endpointId, snap.inventory, now) : 0;
  if (snap.agent) await writeAgentVersion(tx, tenantId, endpointId, snap.agent.version);

  await tx.endpoint.updateMany({
    where: { id: endpointId, tenantId },
    data: {
      ...(snap.updates ? { lastScanAt: now } : {}),
      ...(snap.agent ? { agentVersion: snap.agent.version, goarch: snap.agent.goarch ?? null } : {}),
    },
  });
  return { windows, thirdParty };
}

const stateKey = (endpointId: string, patchId: string) => ({ endpointId_patchId: { endpointId, patchId } });

/** Windows updates (catalog rows are shared; the state rows belong to the bank). */
async function writeWindowsUpdates(tx: Tx, tenantId: string, endpointId: string, updates: readonly UpdateRow[]): Promise<number> {
  const key = (patchId: string) => stateKey(endpointId, patchId);
  const seenPatchIds: string[] = [];
  for (const u of updates) {
    const guid = normGuid(u.guid);
    const patch = await tx.patch.upsert({
      where: { externalId: guid },
      create: {
        kind: "WINDOWS",
        externalId: guid,
        kb: u.kb,
        title: u.title ?? u.kb ?? guid,
        severity: mapSeverity(u.severity),
      },
      update: {},
      select: { id: true },
    });
    seenPatchIds.push(patch.id);
    const status = u.installed ? "INSTALLED" : "NEEDED";
    await tx.endpointPatchState.upsert({
      where: key(patch.id),
      create: { tenantId, endpointId, patchId: patch.id, status, tacticalUpdatePk: u.id },
      update: { status, tacticalUpdatePk: u.id },
    });
  }

  // Updates Tactical no longer reports (superseded / removed) are no longer applicable here.
  await tx.endpointPatchState.updateMany({
    where: {
      tenantId,
      endpointId,
      patch: { kind: "WINDOWS" },
      patchId: { notIn: seenPatchIds },
      status: { in: ["NEEDED", "FAILED"] },
    },
    data: { status: "NOT_APPLICABLE" },
  });
  return updates.length;
}

/** Installed software (fleet discovery) + third-party compliance. */
async function writeInventory(tx: Tx, tenantId: string, endpointId: string, inventory: readonly SoftwareItem[], now: Date): Promise<number> {
  const key = (patchId: string) => stateKey(endpointId, patchId);
  await recordInventory(tx, tenantId, endpointId, inventory);
  let thirdParty = 0;
  for (const r of await currentThirdPartyReleases(tx, tenantId, now)) {
    const status = thirdPartyStatus(inventory, r.inventoryMatch, r.version);
    if (status === null) {
      await tx.endpointPatchState.deleteMany({ where: { tenantId, endpointId, patchId: r.patchId } });
      continue;
    }
    thirdParty++;
    await tx.endpointPatchState.upsert({
      where: key(r.patchId),
      create: { tenantId, endpointId, patchId: r.patchId, status },
      update: { status },
    });
  }
  return thirdParty;
}

/** Tactical agent version (compliance for AGENT_UPGRADE patches). */
async function writeAgentVersion(tx: Tx, tenantId: string, endpointId: string, version: string): Promise<void> {
  const key = (patchId: string) => stateKey(endpointId, patchId);
  // Highest live version (never rely on DB order — two live patches can briefly coexist).
  const liveAgentPatches = await tx.patch.findMany({
    where: { kind: "AGENT_UPGRADE", supersededById: null, agentVersion: { not: null } },
    select: { id: true, agentVersion: true },
  });
  const latestAgentPatch = liveAgentPatches.reduce<(typeof liveAgentPatches)[number] | null>(
    (best, p) => (!best || compareVersions(p.agentVersion!, best.agentVersion!) > 0 ? p : best),
    null,
  );
  if (latestAgentPatch?.agentVersion) {
    const status = compareVersions(version, latestAgentPatch.agentVersion) >= 0 ? "INSTALLED" : "NEEDED";
    await tx.endpointPatchState.upsert({
      where: key(latestAgentPatch.id),
      create: { tenantId, endpointId, patchId: latestAgentPatch.id, status },
      update: { status },
    });
  }
}

/** Read one endpoint from Tactical, then store the result in its bank's scope. */
export async function ingestEndpoint(
  tactical: TacticalClient,
  tenantId: string,
  ep: { id: string; tacticalAgentId: string },
  now = new Date(),
): Promise<{ windows: number; thirdParty: number }> {
  const updates = await tactical.getUpdates(ep.tacticalAgentId);
  const inventory = await tactical.getSoftware(ep.tacticalAgentId);
  const agent = await tactical.getAgent(ep.tacticalAgentId);
  return withTenant(tenantId, (tx) => writeEndpointSnapshot(tx, tenantId, ep.id, { updates, inventory, agent }, now), {
    timeoutMs: INGEST_TX_TIMEOUT_MS,
  });
}

/** Worker step: request rescans and ingest results for the legacy bank's endpoints that are due. */
export async function ingestDueEndpoints(tactical: TacticalClient, now = new Date(), tenantId = legacyTacticalTenantId()) {
  // Once the bank enrols a site connector, its PCs are collected through the connector (COLLECT jobs).
  if (await tenantUsesConnector(tenantId)) return { rescanRequested: 0, ingested: 0, discovery: null, viaConnector: true };
  const db = <T>(fn: (tx: Tx) => Promise<T>): Promise<T> => withTenant(tenantId, fn);
  const scanCutoff = new Date(now.getTime() - SCAN_REQUEST_INTERVAL_MS);
  const toRescan = await db((tx) =>
    tx.endpoint.findMany({
      where: { tenantId, OR: [{ lastScanRequestedAt: null }, { lastScanRequestedAt: { lt: scanCutoff } }] },
      orderBy: { lastScanRequestedAt: { sort: "asc", nulls: "first" } },
      take: BATCH,
      select: { id: true, tacticalAgentId: true },
    }),
  );
  for (const ep of toRescan) {
    let requestedAt = now;
    try {
      await tactical.scanUpdates(ep.tacticalAgentId);
    } catch (err: unknown) {
      // Unreachable PC: retry in ~1h instead of blocking the head of the queue every tick.
      requestedAt = new Date(now.getTime() - SCAN_REQUEST_INTERVAL_MS + RETRY_FAILED_MS);
      log.warn("scan.request_failed", { agentId: ep.tacticalAgentId, err: err instanceof Error ? err.message : String(err) });
    }
    await db((tx) => tx.endpoint.updateMany({ where: { id: ep.id, tenantId }, data: { lastScanRequestedAt: requestedAt } }));
  }

  const readCutoff = new Date(now.getTime() - READ_INTERVAL_MS);
  const attemptCutoff = new Date(now.getTime() - RETRY_FAILED_MS);
  const due = await db((tx) =>
    tx.endpoint.findMany({
      where: {
        tenantId,
        AND: [
          { OR: [{ lastScanAt: null }, { lastScanAt: { lt: readCutoff } }] },
          { OR: [{ ingestAttemptAt: null }, { ingestAttemptAt: { lt: attemptCutoff } }] },
        ],
      },
      orderBy: { ingestAttemptAt: { sort: "asc", nulls: "first" } },
      take: BATCH,
      select: { id: true, tacticalAgentId: true },
    }),
  );
  let ingested = 0;
  for (const ep of due) {
    // Mark the attempt first, so a failing PC moves to the back of the queue.
    await db((tx) => tx.endpoint.updateMany({ where: { id: ep.id, tenantId }, data: { ingestAttemptAt: now } }));
    try {
      await ingestEndpoint(tactical, tenantId, ep, now);
      ingested++;
    } catch (err: unknown) {
      log.warn("scan.ingest_failed", { agentId: ep.tacticalAgentId, err: err instanceof Error ? err.message : String(err) });
    }
  }
  // Fleet discovery is local-only (no internet); rebuild only when new inventory arrived.
  const discovery = ingested > 0 ? await rebuildDiscovered(tenantId) : null;
  return { rescanRequested: toRescan.length, ingested, discovery, viaConnector: false };
}
