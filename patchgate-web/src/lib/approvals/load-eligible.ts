import "server-only";
import type { App, AppVersion, Patch, Prisma } from "@prisma/client";
import { prisma } from "@/lib/db";
import { versionPublisher } from "@/lib/thirdparty/package-from-db";
import { directTacticalConfig, legacyTacticalTenantId } from "@/lib/tactical/from-env";
import { normalizeGuid } from "@/lib/winupdate/microsoft";
import type { EligiblePatch } from "./eligibility";

export type PatchWithApp = Patch & { appVersion: (AppVersion & { app: App }) | null };

type Db = Prisma.TransactionClient;

/** Approved (VERIFIED) mirrored Tactical agent builds, grouped by version. */
export async function verifiedAgentReleases(versions: readonly string[], db: Db = prisma) {
  if (versions.length === 0) return new Map<string, { version: string; sha256: string; repoPath: string; assetName: string }[]>();
  const rows = await db.mirroredRelease.findMany({
    where: { component: "TACTICAL_AGENT", verification: "VERIFIED", version: { in: [...versions] } },
    select: { version: true, sha256: true, repoPath: true, assetName: true },
  });
  const byVersion = new Map<string, typeof rows>();
  for (const r of rows) byVersion.set(r.version, [...(byVersion.get(r.version) ?? []), r]);
  return byVersion;
}

/** Shared apps the bank has opted in to (TenantApp). Call inside withTenant(tenantId). */
export async function enabledAppIds(tx: Db, tenantId: string): Promise<Set<string>> {
  const rows = await tx.tenantApp.findMany({ where: { tenantId }, select: { appId: true } });
  return new Set(rows.map((r) => r.appId));
}

/**
 * Does this bank get Windows updates ONLY through PatchGate's offline scan + cached files (windowsUpdateSource
 * PATCHGATE)? Not for WSUS banks, and not for the legacy bank on the direct Tactical link (lab / pilot path that
 * installs through Tactical). Call inside withTenant(tenantId).
 */
export async function requiresOfflineWindowsScan(tx: Db, tenantId: string): Promise<boolean> {
  if (tenantId === legacyTacticalTenantId() && directTacticalConfig() !== null) return false;
  const source = (await tx.tenant.findUnique({ where: { id: tenantId }, select: { windowsUpdateSource: true } }))?.windowsUpdateSource ?? "PATCHGATE";
  return source === "PATCHGATE";
}

/**
 * PATCHGATE banks: a Windows patch is deliverable only if PatchGate's offline scan reported it (WinUpdate row)
 * and it is not UNRESOLVABLE. Patches listed only by Tactical's own online scan cannot be delivered offline.
 */
async function winUpdateBlocks(patches: readonly PatchWithApp[], db: Db): Promise<Map<string, "not-scanned" | "unresolvable">> {
  const blocks = new Map<string, "not-scanned" | "unresolvable">();
  const win = patches.filter((p) => p.kind === "WINDOWS");
  if (win.length === 0) return blocks;
  const ids = [...new Set(win.flatMap((p) => normalizeGuid(p.externalId) ?? []))];
  const rows = ids.length > 0 ? await db.winUpdate.findMany({ where: { id: { in: ids } }, select: { id: true, catalogState: true } }) : [];
  const state = new Map(rows.map((r) => [r.id, r.catalogState]));
  for (const p of win) {
    const s = state.get(normalizeGuid(p.externalId) ?? "");
    if (s === undefined) blocks.set(p.id, "not-scanned");
    else if (s === "UNRESOLVABLE") blocks.set(p.id, "unresolvable");
  }
  return blocks;
}

/**
 * Map DB patches to the pure eligibility model (one query for all agent builds).
 * Pass the bank's enabled apps to also require the TenantApp opt-in for third-party packages, and
 * opts.requireOfflineScan (requiresOfflineWindowsScan) to require PatchGate's offline-scan evidence for Windows patches.
 */
export async function toEligible(
  patches: readonly PatchWithApp[],
  enabledApps?: ReadonlySet<string>,
  db: Db = prisma,
  opts: { requireOfflineScan?: boolean } = {},
): Promise<EligiblePatch[]> {
  const agentVersions = patches.flatMap((p) => (p.kind === "AGENT_UPGRADE" && p.agentVersion ? [p.agentVersion] : []));
  const releases = await verifiedAgentReleases(agentVersions, db);
  const blocks = opts.requireOfflineScan ? await winUpdateBlocks(patches, db) : new Map<string, "not-scanned" | "unresolvable">();
  return patches.map((p) => ({
    title: p.title,
    kind: p.kind,
    supersededById: p.supersededById,
    appVersion: p.appVersion && {
      ...p.appVersion,
      wingetId: p.appVersion.app.wingetId,
      publisher: versionPublisher(p.appVersion, p.appVersion.app.expectedPublisher),
    },
    agentReleases: p.kind === "AGENT_UPGRADE" && p.agentVersion ? (releases.get(p.agentVersion) ?? []) : undefined,
    tenantAppEnabled: enabledApps && p.kind === "THIRD_PARTY" && p.appVersion ? enabledApps.has(p.appVersion.appId) : undefined,
    winUpdateBlock: blocks.get(p.id),
  }));
}
