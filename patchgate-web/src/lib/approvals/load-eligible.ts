import "server-only";
import type { App, AppVersion, Patch, Prisma } from "@prisma/client";
import { prisma } from "@/lib/db";
import { versionPublisher } from "@/lib/thirdparty/package-from-db";
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
 * Map DB patches to the pure eligibility model (one query for all agent builds).
 * Pass the bank's enabled apps to also require the TenantApp opt-in for third-party packages.
 */
export async function toEligible(
  patches: readonly PatchWithApp[],
  enabledApps?: ReadonlySet<string>,
  db: Db = prisma,
): Promise<EligiblePatch[]> {
  const agentVersions = patches.flatMap((p) => (p.kind === "AGENT_UPGRADE" && p.agentVersion ? [p.agentVersion] : []));
  const releases = await verifiedAgentReleases(agentVersions, db);
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
  }));
}
