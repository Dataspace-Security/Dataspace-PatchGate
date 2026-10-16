import "server-only";
import type { Prisma } from "@prisma/client";
import type { z } from "zod";
import type { JobPackage, resultSchemas } from "@/lib/connector/protocol";
import { latestScanCabPackage } from "./cab";
import { planInstall, recordInstallResult } from "./install";
import { ingestWuScanResult } from "./scan-result";

/**
 * CONTRACT between the connector job pipeline (src/lib/connector/**) and the Windows-update pipeline
 * (src/lib/winupdate/**). The connector side calls ONLY these functions for Windows updates delivered
 * through PatchGate (no WSUS, no internet on PCs). The winupdate side implements them.
 * All functions run inside a tenant-scoped transaction (withTenant) supplied by the caller.
 */

export interface WuJobContext {
  tenantId: string;
  connectorId: string;
  jobId: string;
}

/** Latest verified Microsoft offline scan catalog (wsusscn2.cab) to send with WU_SCAN jobs; null if none yet. */
export async function wuScanCab(tx: Prisma.TransactionClient): Promise<JobPackage | null> {
  return latestScanCabPackage(tx);
}

/** Store a WU_SCAN result: catalog the reported updates/files, per-endpoint applicability, queue file fetches. */
export async function handleWuScanResult(
  tx: Prisma.TransactionClient,
  ctx: WuJobContext,
  result: z.infer<(typeof resultSchemas)["WU_SCAN"]>,
): Promise<void> {
  await ingestWuScanResult(tx, ctx, result);
}

/**
 * Build the WU_INSTALL payload for one endpoint and the given approved WINDOWS patches (Patch ids).
 * Returns null when nothing applies or files are not yet verified. `cacheNeeds` = packages the site cache
 * must hold first (the caller schedules CACHE_PACKAGE jobs and orders them before the install).
 * null is "not now": keep the deployment queued and ask again later (files downloading / in quarantine),
 * up to the caller's own deadline.
 */
export async function planWuInstall(
  tx: Prisma.TransactionClient,
  input: { tenantId: string; endpointId: string; patchIds: string[]; rebootPolicy: "NEVER" | "IF_REQUIRED" | "FORCE" },
): Promise<{ payload: { updates: { updateId: string; kb: string | null; files: JobPackage[] }[]; rebootPolicy: "NEVER" | "IF_REQUIRED" | "FORCE" }; cacheNeeds: JobPackage[] } | null> {
  return planInstall(tx, input);
}

/** Store a WU_INSTALL result (per-update outcome, reboot flag) for the deployment it belongs to. */
export async function handleWuInstallResult(
  tx: Prisma.TransactionClient,
  ctx: WuJobContext & { deploymentId: string | null },
  result: z.infer<(typeof resultSchemas)["WU_INSTALL"]>,
): Promise<void> {
  await recordInstallResult(tx, ctx, result);
}

export { fetchWindowsUpdatesDue } from "./due";
export { winupdatePackageBySha256 } from "./files";
