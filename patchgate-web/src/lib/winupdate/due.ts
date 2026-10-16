import "server-only";
import { prisma } from "@/lib/db";
import { SCAN_CAB_SOURCE, defaultCabDeps, errText, fetchScanCab, type CabDeps } from "./cab";
import { defaultFileDeps, processPendingFiles, type FileDeps } from "./files";
import { defaultResolveDeps, resolvePendingUpdates, type ResolveDeps } from "./resolve";

/** Microsoft re-publishes wsusscn2.cab around Patch Tuesday (+ out of band): a cheap HEAD check daily. */
const CAB_CHECK_INTERVAL_MS = 24 * 60 * 60_000;

/**
 * Hourly fetch-loop step (POST /api/worker/fetch, inside its "fetch" lease): refresh the scan catalog when
 * due, bind newly reported update GUIDs to the Microsoft Update Catalog, then download + verify the bound
 * Microsoft update files (repository quota + byte budgets). Each part fails independently.
 */
export async function fetchWindowsUpdatesDue(
  now = new Date(),
  deps: { cab?: CabDeps; files?: FileDeps; resolve?: ResolveDeps } = {},
): Promise<{ scanCab: string; catalog: Record<string, number> | string; files: Record<string, number | boolean> | string }> {
  let scanCab: string;
  try {
    const last = await prisma.fetchRun.findFirst({ where: { source: SCAN_CAB_SOURCE }, orderBy: { startedAt: "desc" } });
    if (last && now.getTime() - last.startedAt.getTime() < CAB_CHECK_INTERVAL_MS) scanCab = "not due";
    else {
      const r = await fetchScanCab(deps.cab ?? defaultCabDeps());
      scanCab = "reason" in r ? `${r.status}: ${r.reason}` : r.status;
    }
  } catch (err: unknown) {
    scanCab = `FAILED: ${errText(err)}`;
  }
  let catalog: Record<string, number> | string;
  try {
    catalog = await resolvePendingUpdates(deps.resolve ?? defaultResolveDeps(), now);
  } catch (err: unknown) {
    catalog = `FAILED: ${errText(err)}`;
  }
  let files: Record<string, number | boolean> | string;
  try {
    files = await processPendingFiles(deps.files ?? defaultFileDeps(), now);
  } catch (err: unknown) {
    files = `FAILED: ${errText(err)}`;
  }
  return { scanCab, catalog, files };
}
