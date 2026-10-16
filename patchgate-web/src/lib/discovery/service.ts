import "server-only";
import { prisma } from "@/lib/db";
import { env } from "@/lib/env";
import { appendAudit } from "@/lib/audit/service";
import { DomainError } from "@/lib/errors";
import type { SoftwareItem } from "@/lib/tactical/types";
import { withPlatform, withTenant, type Tx } from "@/lib/tenancy";
import { inventoryRows } from "./inventory";
import { matchProduct } from "./match";
import { discoveryKey, inventoryRegexFor, normalizeName, productStem } from "./normalize";
import { openCatalog, refreshWingetIndex } from "./winget-index";

/** Replace one PC's stored inventory with what Tactical reports now (inside withTenant(tenantId)). */
export async function recordInventory(tx: Tx, tenantId: string, endpointId: string, items: readonly SoftwareItem[]): Promise<number> {
  const rows = inventoryRows(items);
  await tx.installedSoftware.deleteMany({ where: { tenantId, endpointId } });
  await tx.installedSoftware.createMany({ data: rows.map((r) => ({ ...r, tenantId, endpointId })), skipDuplicates: true });
  return rows.length;
}

interface ProductGroup {
  normName: string;
  normPublisher: string | null;
  name: string;
  publisher: string | null;
  endpoints: bigint;
  versions: (string | null)[];
  codes: (string | null)[];
}

const MAX_VERSIONS_SHOWN = 20;
const REBUILD_TX_TIMEOUT_MS = 120_000;

/**
 * Rebuild ONE bank's "what is installed" list and match each product to winget (local index only;
 * no internet). Admin choices (managed app, ignored) survive rebuilds; products no longer installed
 * anywhere disappear unless managed. A product counts as managed when the bank has enabled its app.
 */
export async function rebuildDiscovered(tenantId: string): Promise<{ products: number; matched: number; indexAvailable: boolean }> {
  const catalog = await openCatalog(env().REPO_DIR);
  try {
    return await withTenant(
      tenantId,
      async (tx) => {
        const groups = await tx.$queryRaw<ProductGroup[]>`
          SELECT "normName", "normPublisher", MIN("name") AS name, MIN("publisher") AS publisher,
                 COUNT(DISTINCT "endpointId") AS endpoints,
                 ARRAY_AGG(DISTINCT "version") AS versions,
                 ARRAY_AGG(DISTINCT "productCode") AS codes
            FROM "InstalledSoftware"
           WHERE "tenantId" = ${tenantId}
           GROUP BY "normName", "normPublisher"`;

        // Only apps THIS bank opted in to count as managed.
        const enabled = await tx.tenantApp.findMany({ where: { tenantId }, select: { app: { select: { id: true, wingetId: true } } } });
        const appByWinget = new Map(enabled.map((e) => [e.app.wingetId.toLowerCase(), e.app.id]));
        let matched = 0;
        const keys: string[] = [];
        for (const g of groups) {
          const key = discoveryKey(g.normName, g.normPublisher);
          keys.push(key);
          const m = catalog
            ? matchProduct({ name: normalizeName(g.name), normPublisher: g.normPublisher, productCodes: g.codes.filter((c): c is string => !!c) }, catalog)
            : ({ wingetId: null, match: "NONE" } as const);
          if (m.wingetId) matched++;
          const versions = g.versions.filter((v): v is string => !!v).slice(0, MAX_VERSIONS_SHOWN);
          const linked = m.wingetId ? appByWinget.get(m.wingetId.toLowerCase()) : undefined;
          await tx.discoveredApp.upsert({
            where: { tenantId_key: { tenantId, key } },
            create: { tenantId, key, displayName: g.name, publisher: g.publisher, wingetId: m.wingetId, match: m.match, endpointCount: Number(g.endpoints), versions, appId: linked ?? null },
            update: {
              displayName: g.name,
              publisher: g.publisher,
              wingetId: m.wingetId,
              match: m.match,
              endpointCount: Number(g.endpoints),
              versions,
              ...(linked ? { appId: linked } : {}),
            },
          });
        }
        await tx.discoveredApp.deleteMany({ where: { tenantId, key: { notIn: keys }, appId: null } });
        await tx.discoveredApp.updateMany({ where: { tenantId, key: { notIn: keys }, appId: { not: null } }, data: { endpointCount: 0 } });
        return { products: groups.length, matched, indexAvailable: catalog !== null };
      },
      { timeoutMs: REBUILD_TX_TIMEOUT_MS },
    );
  } finally {
    catalog?.close();
  }
}

const DAILY_MS = 24 * 60 * 60_000;
const INDEX_SOURCE = "winget-index";

/** Fetch-loop step: refresh the winget index at most once a day (internet; signed by Microsoft). */
export async function refreshCatalogDue(now = new Date()) {
  const last = await prisma.fetchRun.findFirst({ where: { source: INDEX_SOURCE, ok: true }, orderBy: { startedAt: "desc" } });
  if (last && now.getTime() - last.startedAt.getTime() < DAILY_MS) return { skipped: true };
  const e = env();
  const run = await prisma.fetchRun.create({ data: { source: INDEX_SOURCE } });
  try {
    const r = await refreshWingetIndex({ repoDir: e.REPO_DIR, timeoutMs: e.FETCH_TIMEOUT_MS, codesignCaFile: e.CODESIGN_CA_FILE });
    await prisma.fetchRun.update({ where: { id: run.id }, data: { finishedAt: new Date(), ok: true, message: `${r.packages} packages` } });
    return r;
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message.slice(0, 300) : "unknown error";
    await prisma.fetchRun.update({ where: { id: run.id }, data: { finishedAt: new Date(), ok: false, message } });
    throw err;
  }
}


export interface DiscoveryActor {
  upn: string;
  /** PatchGate platform administrator (tenantId null, role ADMIN): may add to the SHARED allow-list. */
  platformAdmin: boolean;
}

export type ManageResult = { appId: string; requested: false } | { appId: null; requested: true };

/**
 * Admin "Manage" on a discovered product of a bank.
 * - The app is already on the SHARED allow-list → the bank opts in (TenantApp) right away.
 * - It is not → only a PatchGate PLATFORM admin may add it (the fetcher then downloads it daily for everyone).
 *   A bank admin's click records an allow-list REQUEST (bank + platform audit chains) that a platform admin
 *   approves (approveAllowlistRequest) or declines. New entries get NO signer pin (first download HELD until
 *   a platform admin approves the signer), as before.
 */
export async function manageDiscovered(tenantId: string, id: string, who: DiscoveryActor | string): Promise<ManageResult> {
  // A bare UPN (older callers) is a BANK actor: it can never add to the shared allow-list.
  const actor: DiscoveryActor = typeof who === "string" ? { upn: who, platformAdmin: false } : who;
  const r = await withTenant(tenantId, async (tx): Promise<ManageResult & { created: { id: string; wingetId: string; inventoryMatch: string } | null; wingetId: string }> => {
    const d = await tx.discoveredApp.findFirst({ where: { id, tenantId } });
    if (!d) throw new DomainError("Discovered app not found", 404);
    if (!d.wingetId) throw new DomainError("No winget package matched — add it manually on the Apps page", 409);
    if (d.appId) throw new DomainError("Already managed", 409);

    const existing = await tx.app.findUnique({ where: { wingetId: d.wingetId } });
    if (!existing && !actor.platformAdmin) {
      if (d.requestedAt) throw new DomainError("Already requested — waiting for a PatchGate administrator", 409);
      await tx.discoveredApp.update({ where: { id: d.id }, data: { requestedAt: new Date(), requestedBy: actor.upn.slice(0, 200) } });
      await appendAudit(
        { tenantId, actor: actor.upn, action: "discovery.allowlist_requested", entity: "DiscoveredApp", entityId: d.id, payload: { wingetId: d.wingetId, displayName: d.displayName, endpoints: d.endpointCount } },
        tx,
      );
      return { appId: null, requested: true, created: null, wingetId: d.wingetId };
    }
    const app =
      existing ??
      (await tx.app.create({
        data: {
          wingetId: d.wingetId,
          displayName: productStem(d.displayName).slice(0, 100),
          inventoryMatch: inventoryRegexFor(d.displayName),
          expectedPublisher: null,
          allowedDomains: [],
        },
      }));
    await tx.tenantApp.upsert({
      where: { tenantId_appId: { tenantId, appId: app.id } },
      create: { tenantId, appId: app.id, enabledBy: actor.upn },
      update: {},
    });
    const { count } = await tx.discoveredApp.updateMany({ where: { id, tenantId, appId: null }, data: { appId: app.id, ignored: false, requestedAt: null } });
    if (count !== 1) throw new DomainError("Discovered app changed concurrently", 409);
    await appendAudit(
      {
        tenantId,
        actor: actor.upn,
        action: existing ? "discovery.link" : "app.allowlist_add",
        entity: "App",
        entityId: app.id,
        payload: { wingetId: app.wingetId, inventoryMatch: app.inventoryMatch, from: "discovery", endpoints: d.endpointCount, bankEnabled: true, requestedBy: d.requestedBy },
      },
      tx,
    );
    return { appId: app.id, requested: false, created: existing ? null : { id: app.id, wingetId: app.wingetId, inventoryMatch: app.inventoryMatch }, wingetId: d.wingetId };
  });

  // Shared allow-list decisions also belong on the platform chain (PatchGate's SIEM view).
  if (r.requested) {
    await appendAudit({ actor: actor.upn, action: "discovery.allowlist_requested", entity: "DiscoveredApp", entityId: id, payload: { tenantId, wingetId: r.wingetId }, tenantId: null });
    return { appId: null, requested: true };
  }
  if (r.created) {
    await appendAudit({ actor: actor.upn, action: "app.allowlist_add", entity: "App", entityId: r.created.id, payload: { wingetId: r.created.wingetId, inventoryMatch: r.created.inventoryMatch, from: "discovery", tenantId }, tenantId: null });
  }
  return { appId: r.appId!, requested: false };
}

export interface AllowlistRequest {
  id: string;
  tenantId: string;
  tenantName: string;
  displayName: string;
  publisher: string | null;
  wingetId: string;
  endpointCount: number;
  requestedAt: Date;
  requestedBy: string | null;
}

/** Platform admins: pending shared allow-list requests from every bank. */
export async function listAllowlistRequests(): Promise<AllowlistRequest[]> {
  const rows = await withPlatform((tx) =>
    tx.discoveredApp.findMany({
      where: { requestedAt: { not: null }, appId: null, wingetId: { not: null } },
      orderBy: { requestedAt: "asc" },
      take: 200,
      include: { tenant: { select: { name: true } } },
    }),
  );
  return rows.map((r) => ({
    id: r.id,
    tenantId: r.tenantId,
    tenantName: r.tenant.name,
    displayName: r.displayName,
    publisher: r.publisher,
    wingetId: r.wingetId!,
    endpointCount: r.endpointCount,
    requestedAt: r.requestedAt!,
    requestedBy: r.requestedBy,
  }));
}

async function requestTenant(id: string): Promise<string> {
  const row = await withPlatform((tx) => tx.discoveredApp.findUnique({ where: { id }, select: { tenantId: true, requestedAt: true, appId: true } }));
  if (!row || !row.requestedAt || row.appId) throw new DomainError("Allow-list request not found", 404);
  return row.tenantId;
}

/** Platform admin approves a bank's request: adds the app to the shared allow-list and opts that bank in. */
export async function approveAllowlistRequest(id: string, actorUpn: string): Promise<ManageResult> {
  return manageDiscovered(await requestTenant(id), id, { upn: actorUpn, platformAdmin: true });
}

/** Platform admin declines a bank's request (audited on both chains; the bank may request again). */
export async function declineAllowlistRequest(id: string, actorUpn: string, reason: string): Promise<void> {
  const tenantId = await requestTenant(id);
  const why = reason.trim().slice(0, 500) || "declined";
  await withTenant(tenantId, async (tx) => {
    await tx.discoveredApp.updateMany({ where: { id, tenantId }, data: { requestedAt: null, requestedBy: null } });
    await appendAudit({ tenantId, actor: actorUpn, action: "discovery.allowlist_declined", entity: "DiscoveredApp", entityId: id, payload: { reason: why } }, tx);
  });
  await appendAudit({ actor: actorUpn, action: "discovery.allowlist_declined", entity: "DiscoveredApp", entityId: id, payload: { tenantId, reason: why }, tenantId: null });
}

/** Bank admin: hide (or un-hide) a discovered product that the bank does not patch through PatchGate. */
export async function setDiscoveredIgnored(tenantId: string, id: string, ignored: boolean, actorUpn: string): Promise<void> {
  await withTenant(tenantId, async (tx) => {
    const { count } = await tx.discoveredApp.updateMany({ where: { id, tenantId }, data: { ignored } });
    if (count !== 1) throw new DomainError("Discovered app not found", 404);
    await appendAudit(
      { tenantId, actor: actorUpn, action: ignored ? "discovery.ignore" : "discovery.unignore", entity: "DiscoveredApp", entityId: id, payload: {} },
      tx,
    );
  });
}
