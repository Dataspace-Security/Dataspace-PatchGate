import type { CacheIndex } from "../cache/cache-index.ts";
import type { JobPackage, JobPayload } from "../protocol.ts";
import { TacticalError, type TacticalClient } from "../tactical/client.ts";
import { mapPool } from "../util/semaphore.ts";
import type { Logger } from "../util/log.ts";
import { permanent, toJobError, transient } from "./errors.ts";
import type { JobResultFor } from "./executors.ts";
import { assertScanCab, parseScanOutput } from "./wu-parse.ts";

/** Script ids + timeouts for the two PC-side Windows-update scripts (from tactical.* config, never from a job). */
export interface WuConfig {
  scanScriptId?: number;
  installScriptId?: number;
  scanTimeoutSec: number;
  installTimeoutSec: number;
}

export interface WuDeps {
  tactical: TacticalClient;
  index: CacheIndex;
  cacheBaseUrl: string;
  maxParallelCalls: number;
  wu?: WuConfig;
  log: Logger;
}

/** Package must be in THIS site's verified cache, unchanged (shared with WU_INSTALL). */
export async function assertCached(d: Pick<WuDeps, "index">, pkg: JobPackage): Promise<void> {
  const entry = d.index.get(pkg.repoPath);
  if (!entry) throw transient(`${pkg.repoPath} is not in this site's cache (run CACHE_PACKAGE first)`);
  if (entry.sha256 !== pkg.sha256 || entry.size !== pkg.size) throw permanent(`cached ${pkg.repoPath} differs from the job (SHA-256/size)`);
  if (!(await d.index.verify(pkg.repoPath))) {
    await d.index.remove(pkg.repoPath);
    throw permanent(`cached ${pkg.repoPath} failed its SHA-256 re-check and was removed from the cache`);
  }
  d.index.touch(pkg.repoPath);
}

/**
 * WU_SCAN: run the signed, read-only offline scan script on each agent. The PC copies wsusscn2.cab from
 * the site cache, verifies it, scans, and prints the applicable updates + their Microsoft URLs.
 * Per-agent failures are reported per agent; the batch fails (retryable) only if Tactical is unreachable.
 */
export async function wuScan(d: WuDeps, p: JobPayload<"WU_SCAN">): Promise<JobResultFor<"WU_SCAN">> {
  const scriptId = d.wu?.scanScriptId;
  if (!scriptId) throw permanent("tactical.wuScanScriptId is not configured on this connector");
  assertScanCab(p.scanCab);
  await assertCached(d, p.scanCab);
  const timeoutSec = d.wu?.scanTimeoutSec ?? 3600;

  const errors: unknown[] = [];
  const agents = await mapPool(p.agentIds, d.maxParallelCalls, async (agentId) => {
    try {
      const out = await d.tactical.runScript(agentId, {
        scriptId,
        timeoutSec,
        envVars: {
          PG_REPO_URL: d.cacheBaseUrl,
          PG_PATH: p.scanCab.repoPath,
          PG_SHA256: p.scanCab.sha256,
          // leave the script time to report before Tactical kills it
          PG_SCAN_TIMEOUT_SEC: String(Math.max(60, timeoutSec - 120)),
        },
      });
      return parseScanOutput(agentId, out);
    } catch (err) {
      errors.push(err);
      return { agentId, error: toJobError(err).message.slice(0, 2000) };
    }
  });
  if (p.agentIds.length > 0 && errors.length === p.agentIds.length && errors.every((e) => e instanceof TacticalError && e.status === undefined)) {
    throw transient(`Tactical unreachable: ${toJobError(errors[0]).message}`);
  }
  const ok = agents.filter((a) => a.updates).length;
  d.log.info("offline Windows Update scan finished", { agents: p.agentIds.length, ok, failed: p.agentIds.length - ok });
  return { agents };
}
