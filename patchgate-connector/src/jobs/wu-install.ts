import type { JobPayload } from "../protocol.ts";
import { isRunScriptOutcomeUnknown } from "../tactical/client.ts";
import { outcomeUnknown, permanent } from "./errors.ts";
import type { JobResultFor } from "./executors.ts";
import { batchUpdates, NO_RESULT_LINE, parseInstallOutput, updateEntries } from "./wu-parse.ts";
import { assertCached, type WuDeps } from "./wu-scan.ts";

/**
 * WU_INSTALL: install approved Microsoft update files on ONE agent with the signed install script.
 * Every file must be in this site's verified cache (re-hashed here; the PC re-checks SHA-256 + Microsoft
 * signature). Updates are passed in batches that fit the script's environment; the reboot policy applies
 * to the last batch only (earlier batches never restart the PC). Safe to re-run: the script skips
 * updates that are already installed.
 */
export async function wuInstall(d: WuDeps, p: JobPayload<"WU_INSTALL">): Promise<JobResultFor<"WU_INSTALL">> {
  const scriptId = d.wu?.installScriptId;
  if (!scriptId) throw permanent("tactical.wuInstallScriptId is not configured on this connector");
  const timeoutSec = d.wu?.installTimeoutSec ?? 3600;

  const updates = p.updates.map((u) => ({ updateId: u.updateId.toLowerCase(), entries: updateEntries(u) }));
  for (const u of p.updates) for (const f of u.files) await assertCached(d, f);
  const batches = batchUpdates(updates);

  const installed = new Set<string>(); // installed now or already before (PatchGate marks both INSTALLED)
  let fresh = 0;
  const failed = new Map<string, string>();
  let rebootRequired = false;
  let stop: string | null = null;

  for (const [i, batch] of batches.entries()) {
    const ids = batch.map((u) => u.updateId);
    if (stop) {
      for (const id of ids) failed.set(id, stop);
      continue;
    }
    const last = i === batches.length - 1;
    let out: string;
    try {
      out = await d.tactical.runScript(p.agentId, {
        scriptId,
        timeoutSec,
        envVars: {
          PG_REPO_URL: d.cacheBaseUrl,
          PG_UPDATES: batch.flatMap((u) => u.entries).join(";"),
          PG_REBOOT: last ? p.rebootPolicy : "NEVER",
          PG_DEADLINE_SEC: String(Math.max(60, timeoutSec - 120)),
        },
      });
    } catch (err) {
      // No answer / proxy gateway error (408/502/503/504) / timeout = the script may still be running on
      // the PC: never start another one (no retry, no further batches).
      const unknown = isRunScriptOutcomeUnknown(err);
      if (i === 0) {
        if (unknown) throw outcomeUnknown(`install result unknown (${(err as Error).message}); confirm with WU_SCAN`);
        throw err; // nothing ran: normal retry rules (e.g. agent offline)
      }
      const why = unknown ? `install result unknown (${(err as Error).message}); confirm with WU_SCAN` : `script run failed: ${(err as Error).message}`;
      for (const id of ids) failed.set(id, why.slice(0, 2000));
      stop = "not attempted: an earlier batch did not complete";
      continue;
    }
    const r = parseInstallOutput(out);
    if (!r.ok && r.error === NO_RESULT_LINE) {
      // Tactical answers "timeout" (no result line) when the run did not finish in time: wusa/DISM may
      // still be running. Report unknown; never run further batches on this PC now.
      const why = "install result unknown (no result line: the run timed out or was killed); confirm with WU_SCAN";
      if (i === 0) throw outcomeUnknown(why);
      for (const id of ids) failed.set(id, why);
      stop = "not attempted: an earlier batch did not complete";
      continue;
    }
    if (!r.ok) {
      if (batches.length === 1) throw permanent(`install script: ${r.error}`);
      for (const id of ids) failed.set(id, `install script: ${r.error}`.slice(0, 2000));
      continue;
    }
    const inBatch = new Set(ids);
    for (const id of r.run.installed) if (inBatch.has(id.toLowerCase())) fresh++;
    for (const id of [...r.run.installed, ...r.run.skipped]) if (inBatch.has(id.toLowerCase())) installed.add(id.toLowerCase());
    for (const f of r.run.failed) {
      const id = f.updateId.toLowerCase();
      if (inBatch.has(id) && !installed.has(id)) failed.set(id, f.error.slice(0, 2000));
    }
    for (const id of ids) if (!installed.has(id) && !failed.has(id)) failed.set(id, "not reported by install script");
    rebootRequired ||= r.run.rebootRequired;
    if (r.run.rebootScheduled) d.log.info("restart scheduled by install script", { agentId: p.agentId });
  }

  const outcome = failed.size > 0 ? "PARTIAL" : fresh > 0 ? "INSTALLED" : "NOTHING_TO_DO";
  d.log.info("Windows updates installed", { agentId: p.agentId, installed: installed.size, failed: failed.size, rebootRequired });
  return {
    outcome,
    installed: [...installed],
    failed: [...failed.entries()].map(([updateId, error]) => ({ updateId, error })),
    rebootRequired,
  };
}
