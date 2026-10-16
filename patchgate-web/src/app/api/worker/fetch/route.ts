import { env } from "@/lib/env";
import { fail, handle, ok } from "@/lib/api/response";
import { tokenMatches } from "@/lib/api/token";
import { withLease } from "@/lib/deploy/lease";
import { fetchDueApps } from "@/lib/fetch/thirdparty";
import { mirrorTacticalDue } from "@/lib/fetch/tactical";
import { refreshCatalogDue } from "@/lib/discovery/service";
import { fetchWindowsUpdatesDue } from "@/lib/winupdate";

/**
 * Slow loop (internet downloads) — call hourly; each source refreshes at most once a day:
 *   curl -X POST -H "x-worker-token: $WORKER_TOKEN" https://localhost/api/worker/fetch
 * This is the ONLY entry point that causes PatchGate to reach the internet.
 */
async function runFetch(): Promise<Record<string, unknown>> {
  const result: Record<string, unknown> = {};
  try {
    result.apps = await fetchDueApps();
  } catch (err: unknown) {
    result.apps = `FAILED: ${err instanceof Error ? err.message : "unknown"}`;
  }
  try {
    result.tactical = await mirrorTacticalDue();
  } catch (err: unknown) {
    result.tactical = `FAILED: ${err instanceof Error ? err.message : "unknown"}`;
  }
  try {
    result.catalogIndex = await refreshCatalogDue();
  } catch (err: unknown) {
    result.catalogIndex = `FAILED: ${err instanceof Error ? err.message : "unknown"}`;
  }
  try {
    // Microsoft offline scan catalog + update files PCs reported as needed (verified, quarantined).
    result.windowsUpdates = await fetchWindowsUpdatesDue();
  } catch (err: unknown) {
    result.windowsUpdates = `FAILED: ${err instanceof Error ? err.message : "unknown"}`;
  }
  return result;
}

export async function POST(req: Request): Promise<Response> {
  return handle(async () => {
    if (!tokenMatches(req.headers.get("x-worker-token"), env().WORKER_TOKEN)) {
      return fail("Unauthorized", 401);
    }
    // Large downloads take time: never run two fetches concurrently (lease expires after 2 h).
    const result = await withLease("fetch", 2 * 60 * 60_000, runFetch);
    return ok(result ?? { skipped: "another fetch is still running" });
  });
}
