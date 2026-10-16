import "server-only";
import type { Prisma } from "@prisma/client";
import type { z } from "zod";
import { appendAudit } from "@/lib/audit/service";
import { enqueueNotification } from "@/lib/notify/enqueue";
import type { resultSchemas } from "@/lib/connector/protocol";
import { mapSeverity } from "@/lib/scan/map";
import { normalizeGuid, pendingTitle } from "./microsoft";
import { wuLockDetail, wuLockTransition, type WuLockReport } from "./wu-lock";

type Tx = Prisma.TransactionClient;
export type WuScanResult = z.infer<(typeof resultSchemas)["WU_SCAN"]>;
type ScanUpdate = NonNullable<WuScanResult["agents"][number]["updates"]>[number];

export interface WuScanContext {
  tenantId: string;
  connectorId: string;
  jobId: string;
}

/** New update GUIDs one scan result may introduce (the rest are picked up by a later scan). */
export const MAX_NEW_UPDATES_PER_SCAN = 500;

interface CatalogStats {
  newUpdates: number;
  deferredNewUpdates: number;
  /** File lists in the report: never used (the binding comes from the Microsoft Update Catalog). */
  reportedFilesIgnored: number;
}

/**
 * Shared catalog: a PC report only tells us WHICH update GUIDs apply. New GUIDs get a WinUpdate row in
 * state PENDING (placeholder title, no KB/severity/files) and a Patch row with the same placeholder; the
 * fetch loop then binds title/KB/severity/files from the Microsoft Update Catalog (resolve.ts). Nothing the
 * PC says about title, KB, severity, revision or files is stored or shown to any bank.
 */
async function catalogUpdates(tx: Tx, tenantId: string, updates: Map<string, ScanUpdate>): Promise<{ patchIds: Map<string, string>; stats: CatalogStats }> {
  const stats: CatalogStats = { newUpdates: 0, deferredNewUpdates: 0, reportedFilesIgnored: 0 };
  const patchIds = new Map<string, string>();
  const ids = [...updates.keys()];
  const existing = new Set((await tx.winUpdate.findMany({ where: { id: { in: ids } }, select: { id: true } })).map((w) => w.id));

  for (const [id, u] of updates) {
    stats.reportedFilesIgnored += u.files.length;
    if (!existing.has(id)) {
      if (stats.newUpdates >= MAX_NEW_UPDATES_PER_SCAN) {
        stats.deferredNewUpdates++;
        continue;
      }
      await tx.winUpdate.createMany({ data: [{ id, revision: 0, title: pendingTitle(id), firstTenantId: tenantId }], skipDuplicates: true });
      stats.newUpdates++;
    }
    const patch = await tx.patch.upsert({
      where: { externalId: id },
      create: { kind: "WINDOWS", externalId: id, kb: null, title: pendingTitle(id), classification: null, severity: mapSeverity(null) },
      update: {},
      select: { id: true, kind: true },
    });
    if (patch.kind === "WINDOWS") patchIds.set(id, patch.id);
  }
  return { patchIds, stats };
}

/** Per-PC applicability (bank data, RLS): reported → NEEDED, previously needed but no longer reported → NOT_APPLICABLE. */
async function writeApplicability(tx: Tx, tenantId: string, endpointId: string, patchIds: string[]): Promise<void> {
  const current = await tx.endpointPatchState.findMany({
    where: { tenantId, endpointId, patch: { kind: "WINDOWS" } },
    select: { patchId: true, status: true },
  });
  const have = new Map(current.map((s) => [s.patchId, s.status]));
  const create = patchIds.filter((p) => !have.has(p));
  if (create.length > 0) {
    await tx.endpointPatchState.createMany({ data: create.map((patchId) => ({ tenantId, endpointId, patchId, status: "NEEDED" as const })), skipDuplicates: true });
  }
  const reNeeded = patchIds.filter((p) => have.has(p) && have.get(p) !== "NEEDED");
  if (reNeeded.length > 0) {
    await tx.endpointPatchState.updateMany({ where: { tenantId, endpointId, patchId: { in: reNeeded } }, data: { status: "NEEDED", lastResult: "offered by offline scan" } });
  }
  await tx.endpointPatchState.updateMany({
    where: { tenantId, endpointId, patch: { kind: "WINDOWS" }, patchId: { notIn: patchIds }, status: { in: ["NEEDED", "FAILED"] } },
    data: { status: "NOT_APPLICABLE", lastResult: "not offered by offline scan (installed or superseded)" },
  });
}

/**
 * Store the PC's Windows Update lock report; audit (bank chain) when it breaks / is restored.
 * Returns true when the PC just became NOT locked (the caller sends one notification per scan result).
 */
async function writeWuLock(tx: Tx, ctx: WuScanContext, endpoint: { id: string; hostname: string; wuLocked: boolean | null }, lock: WuLockReport, now: Date): Promise<boolean> {
  const detail = wuLockDetail(lock);
  await tx.endpoint.updateMany({
    where: { id: endpoint.id, tenantId: ctx.tenantId },
    data: { wuLocked: lock.locked, wuLockCheckedAt: now, wuLockDetail: detail as unknown as Prisma.InputJsonValue },
  });
  const transition = wuLockTransition(endpoint.wuLocked, lock.locked);
  if (transition === "none") return false;
  await appendAudit(
    {
      tenantId: ctx.tenantId,
      actor: `connector:${ctx.connectorId}`,
      action: transition === "broken" ? "endpoint.wu_lock_broken" : "endpoint.wu_lock_restored",
      entity: "Endpoint",
      entityId: endpoint.id,
      payload: { hostname: endpoint.hostname, previous: endpoint.wuLocked, ...detail },
    },
    tx,
  );
  return transition === "broken";
}

/** Store a WU_SCAN result (inside withTenant(ctx.tenantId)). */
export async function ingestWuScanResult(tx: Tx, ctx: WuScanContext, result: WuScanResult, now = new Date()): Promise<void> {
  const agentIds = result.agents.map((a) => a.agentId);
  const endpoints = await tx.endpoint.findMany({
    where: { tenantId: ctx.tenantId, tacticalAgentId: { in: agentIds } },
    select: { id: true, tacticalAgentId: true, connectorId: true, hostname: true, wuLocked: true },
  });
  // An agent belongs to exactly one site connector: ignore reports about another connector's PCs.
  const own = endpoints.filter((e) => e.connectorId === null || e.connectorId === ctx.connectorId);
  const byAgent = new Map(own.map((e) => [e.tacticalAgentId, e.id]));
  const endpointById = new Map(own.map((e) => [e.id, e]));

  const updates = new Map<string, ScanUpdate>();
  let unknownAgents = 0;
  let invalidIds = 0;
  for (const a of result.agents) {
    if (!byAgent.has(a.agentId)) {
      unknownAgents++;
      continue;
    }
    for (const u of a.updates ?? []) {
      const id = normalizeGuid(u.updateId);
      if (!id) {
        invalidIds++;
        continue;
      }
      if (!updates.has(id)) updates.set(id, u);
    }
  }

  const { patchIds, stats } = await catalogUpdates(tx, ctx.tenantId, updates);

  let scanned = 0;
  let failed = 0;
  const lockBroken: { hostname: string; issues: string[] }[] = [];
  for (const a of result.agents) {
    const endpointId = byAgent.get(a.agentId);
    if (!endpointId) continue;
    const endpoint = endpointById.get(endpointId)!;
    // Reported also when the scan itself failed (the lock check runs first on the PC).
    if (a.wuLock && (await writeWuLock(tx, ctx, endpoint, a.wuLock, now))) lockBroken.push({ hostname: endpoint.hostname, issues: a.wuLock.issues });
    if (a.error !== undefined || a.updates === undefined) {
      failed++;
      await tx.endpoint.updateMany({ where: { id: endpointId, tenantId: ctx.tenantId }, data: { lastWuScanError: (a.error ?? "no result").slice(0, 500) } });
      continue;
    }
    scanned++;
    const ids = a.updates.map((u) => normalizeGuid(u.updateId)).flatMap((g) => (g && patchIds.has(g) ? [patchIds.get(g)!] : []));
    await writeApplicability(tx, ctx.tenantId, endpointId, [...new Set(ids)]);
    await tx.endpoint.updateMany({ where: { id: endpointId, tenantId: ctx.tenantId }, data: { lastWuScanAt: now, lastScanAt: now, lastWuScanError: null } });
  }

  await appendAudit(
    {
      tenantId: ctx.tenantId,
      actor: `connector:${ctx.connectorId}`,
      action: "winupdate.scan_ingested",
      entity: "ConnectorJob",
      entityId: ctx.jobId,
      payload: { agents: result.agents.length, scanned, failed, unknownAgents, invalidIds, updates: updates.size, wuLockBroken: lockBroken.length, ...stats },
    },
    tx,
  );
  if (lockBroken.length > 0) await enqueueNotification(tx, { event: "WU_LOCK_BROKEN", tenantId: ctx.tenantId, connectorId: ctx.connectorId, endpoints: lockBroken });
}
