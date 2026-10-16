import type { z } from "zod";
import type { CacheDownloader } from "../cache/download.ts";
import type { CacheIndex } from "../cache/cache-index.ts";
import { resultSchemas, type JobPayload, type JobType } from "../protocol.ts";
import { isRunScriptOutcomeUnknown, TacticalError, type TacticalClient } from "../tactical/client.ts";
import { buildDeployPlan, checkApprovalState } from "../tactical/deploy-plan.ts";
import type { TacticalWinUpdate } from "../tactical/types.ts";
import { mapPool } from "../util/semaphore.ts";
import { errorMessage, type Logger } from "../util/log.ts";
import { JobError, outcomeUnknown, permanent, toJobError, transient } from "./errors.ts";
import { assertDeployablePackage, compareVersions, isTransientInstallFailure, NO_RESULT_LINE, parseInstallResult, toInstallEnv } from "./package-input.ts";
import { fitCollectResult, MAX_RESULT_BYTES } from "./result-size.ts";
import { assertTrustedPackage, type TrustPolicy } from "./trust-policy.ts";
import { wuInstall } from "./wu-install.ts";
import { wuScan, type WuConfig } from "./wu-scan.ts";
import { tacticalAuditSync } from "./tactical-audit.ts";
import type { TacticalGuard } from "../guard/tactical-guard.ts";

/**
 * Typed job executors. Each maps one signed, schema-validated payload to a fixed sequence of
 * Tactical calls. There is no path from a job to an arbitrary Tactical endpoint or script.
 */

export interface ExecutorDeps {
  tactical: TacticalClient;
  index: CacheIndex;
  downloader: CacheDownloader;
  /** PG_REPO_URL handed to the install script: this connector's cache (cache.baseUrl). */
  cacheBaseUrl: string;
  installScriptId?: number;
  installScriptTimeoutSec: number;
  maxParallelCalls: number;
  /** Windows updates through PatchGate (WU_SCAN / WU_INSTALL): fixed Tactical script ids from config. */
  wu?: WuConfig;
  log: Logger;
  signal?: AbortSignal;
  /** Called after SYNC_AGENTS with the number of agents (feeds the heartbeat). */
  onAgentCount?: (n: number) => void;
  /** Optional bank-held trust policy (config `trust`); applied to CACHE_PACKAGE and DEPLOY_PACKAGE. */
  trust?: TrustPolicy;
  /** Cap on one serialised COLLECT result (tests lower it). */
  maxResultBytes?: number;
  /** Real-time Tactical guard (protocol §8): allow-set, and leaves PCs alone while a job changes their approvals. */
  guard?: TacticalGuard;
}

/** Run an approval-changing job on one PC without the guard touching that PC meanwhile. */
const guarded = <T>(d: ExecutorDeps, agentId: string, fn: () => Promise<T>): Promise<T> => (d.guard ? d.guard.busyAgent(agentId, fn) : fn());

/** Protocol maximum of agents in one SYNC_AGENTS result (resultSchemas.SYNC_AGENTS). */
export const MAX_SYNC_AGENTS = 10_000;

export type JobResultFor<T extends JobType> = z.infer<(typeof resultSchemas)[T]>;

const AGENT_ID_RE = /^[A-Za-z0-9_-]{6,64}$/;
const clip = (s: string | null | undefined, max: number): string | null | undefined => (typeof s === "string" ? s.slice(0, max) : s);
const clipTail = (s: string, max: number): string => (s.length > max ? s.slice(s.length - max) : s);
/** Tactical boot_time (epoch seconds, float; sometimes a numeric string) → finite number or null. */
const epochOrNull = (v: unknown): number | null => {
  const n = typeof v === "number" ? v : typeof v === "string" && /^\d+(?:\.\d+)?$/.test(v.trim()) ? Number(v) : NaN;
  return Number.isFinite(n) && n > 0 ? n : null;
};

/** If every per-agent call failed because Tactical itself is unreachable, fail the batch (retryable). */
function assertTacticalReachable(errors: unknown[], total: number): void {
  if (total > 0 && errors.length === total && errors.every((e) => e instanceof TacticalError && e.status === undefined)) {
    throw transient(`Tactical unreachable: ${errorMessage(errors[0])}`);
  }
}

async function syncAgents(d: ExecutorDeps): Promise<JobResultFor<"SYNC_AGENTS">> {
  const agents = await d.tactical.listAgents();
  const valid = agents.filter((a) => AGENT_ID_RE.test(a.agent_id));
  if (valid.length !== agents.length) d.log.warn("agents with unexpected ids skipped", { skipped: agents.length - valid.length });
  d.onAgentCount?.(valid.length);
  if (valid.length > MAX_SYNC_AGENTS) {
    // Never truncate: PatchGate treats the list as complete and would unassign every agent left out.
    throw permanent(
      `Tactical returned ${valid.length} agents; one SYNC_AGENTS result holds at most ${MAX_SYNC_AGENTS}. ` +
        "Not truncating (PatchGate would unassign the rest): split this Tactical server into more sites.",
    );
  }
  const out = valid.map((a) => ({
    agentId: a.agent_id,
    hostname: a.hostname.slice(0, 255),
    site: clip(a.site_name, 255),
    client: clip(a.client_name, 255),
    os: clip(a.operating_system, 255),
    goarch: clip(a.goarch, 16),
    version: clip(a.version, 40),
    online: a.status ? a.status === "online" : null,
    lastSeen: typeof a.last_seen === "string" ? a.last_seen.slice(0, 64) : null,
    bootTime: epochOrNull(a.boot_time),
  }));
  return { agents: out };
}

async function scan(d: ExecutorDeps, p: JobPayload<"SCAN">): Promise<JobResultFor<"SCAN">> {
  const errors: unknown[] = [];
  const outcome = await mapPool(p.agentIds, d.maxParallelCalls, async (agentId) => {
    try {
      await d.tactical.scanUpdates(agentId);
      return { agentId, error: null as string | null };
    } catch (err) {
      errors.push(err);
      return { agentId, error: toJobError(err).message.slice(0, 2000) };
    }
  });
  assertTacticalReachable(errors, p.agentIds.length);
  return {
    requested: outcome.filter((o) => o.error === null).map((o) => o.agentId),
    failed: outcome.filter((o) => o.error !== null).map((o) => ({ agentId: o.agentId, error: o.error as string })),
  };
}

function mapUpdates(list: TacticalWinUpdate[]) {
  return list.slice(0, 2000).map((u) => ({
    id: u.id,
    guid: u.guid.slice(0, 64),
    kb: clip(u.kb, 64) ?? null,
    title: clip(u.title, 1000) ?? null,
    installed: u.installed,
    action: u.action,
    severity: clip(u.severity, 32) ?? null,
  }));
}

async function collect(d: ExecutorDeps, p: JobPayload<"COLLECT">): Promise<JobResultFor<"COLLECT">> {
  const errors: unknown[] = [];
  const agents = await mapPool(p.agentIds, d.maxParallelCalls, async (agentId) => {
    const row: JobResultFor<"COLLECT">["agents"][number] = { agentId };
    try {
      if (p.updates) row.updates = mapUpdates(await d.tactical.getUpdates(agentId));
      if (p.software) {
        row.software = (await d.tactical.getSoftware(agentId)).slice(0, 3000).map((s) => ({
          name: s.name.slice(0, 300),
          version: (s.version ?? "").slice(0, 100),
          publisher: clip(s.publisher, 300),
          uninstall: clip(s.uninstall, 2000),
        }));
      }
      if (p.agent) {
        const a = await d.tactical.getAgent(agentId);
        row.agent = { version: a.version.slice(0, 40), goarch: clip(a.goarch, 16) };
      }
    } catch (err) {
      errors.push(err);
      return { agentId, error: toJobError(err).message.slice(0, 2000) }; // per-agent errors don't fail the batch
    }
    return row;
  });
  assertTacticalReachable(errors, p.agentIds.length);
  const max = d.maxResultBytes ?? MAX_RESULT_BYTES;
  const fitted = fitCollectResult(agents, max);
  if (fitted.trimmed > 0) d.log.warn("COLLECT result too large; lists dropped for some agents (marked per agent)", { agents: fitted.trimmed, maxBytes: max });
  return { agents: fitted.agents };
}

async function resetPending(d: ExecutorDeps, agentId: string, updates: readonly TacticalWinUpdate[]): Promise<number> {
  let n = 0;
  for (const u of updates) {
    if (!u.installed && (u.action === "approve" || u.action === "inherit")) {
      await d.tactical.setUpdateAction(u.id, "nothing");
      n++;
    }
  }
  if (n > 0) d.log.info("approvals reset", { agentId, reset: n });
  return n;
}

async function deployWindows(d: ExecutorDeps, p: JobPayload<"DEPLOY_WINDOWS">): Promise<JobResultFor<"DEPLOY_WINDOWS">> {
  const plan = buildDeployPlan(await d.tactical.getUpdates(p.agentId), new Set(p.guids));
  if (plan.missingOnAgent.length > 0) d.log.info("requested updates not offered on agent", { agentId: p.agentId, missing: plan.missingOnAgent.length });

  // Reset first so Tactical never holds a foreign approval when install fires.
  for (const pk of plan.toReset) await d.tactical.setUpdateAction(pk, "nothing");
  if (plan.installTargets.length === 0) return { outcome: "NOTHING_TO_DO", approved: [] };

  try {
    for (const pk of plan.toApprove) await d.tactical.setUpdateAction(pk, "approve");
    const after = await d.tactical.getUpdates(p.agentId);
    const check = checkApprovalState(after, plan.installTargets);
    if (!check.ok) {
      await resetPending(d, p.agentId, after); // fail safe: nothing stays approved
      throw permanent(
        `Tactical approval state mismatch (unexpected: ${check.unexpected.join(",") || "-"}; missing: ${check.missing.join(",") || "-"}). ` +
          "Set every Tactical patch-policy severity to 'manual'.",
      );
    }
  } catch (err) {
    if (!(err instanceof JobError)) {
      // best effort: withdraw approvals we may have set before the failure
      try {
        await resetPending(d, p.agentId, await d.tactical.getUpdates(p.agentId));
      } catch (cleanupErr) {
        d.log.warn("could not withdraw approvals after failure", { agentId: p.agentId, err: cleanupErr });
      }
    }
    throw err;
  }
  await d.tactical.installApproved(p.agentId);
  return { outcome: "INSTALL_STARTED", approved: plan.installTargets };
}

async function resetApprovals(d: ExecutorDeps, p: JobPayload<"RESET_APPROVALS">): Promise<JobResultFor<"RESET_APPROVALS">> {
  return { reset: await resetPending(d, p.agentId, await d.tactical.getUpdates(p.agentId)) };
}

async function cachePackage(d: ExecutorDeps, p: JobPayload<"CACHE_PACKAGE">): Promise<JobResultFor<"CACHE_PACKAGE">> {
  assertTrustedPackage(p.package, d.trust, d.log, "CACHE_PACKAGE");
  return d.downloader.cache(p.package, d.signal);
}

async function deployPackage(d: ExecutorDeps, p: JobPayload<"DEPLOY_PACKAGE">): Promise<JobResultFor<"DEPLOY_PACKAGE">> {
  const pkg = p.package;
  if (!d.installScriptId) throw permanent("tactical.installScriptId is not configured on this connector");
  assertDeployablePackage(pkg);
  assertTrustedPackage(pkg, d.trust, d.log, "DEPLOY_PACKAGE");

  const entry = d.index.get(pkg.repoPath);
  if (!entry) throw transient("package is not in this site's cache (run CACHE_PACKAGE first)");
  if (entry.sha256 !== pkg.sha256 || entry.size !== pkg.size) throw permanent("cached package differs from the job (SHA-256/size)");
  if (!(await d.index.verify(pkg.repoPath))) {
    await d.index.remove(pkg.repoPath);
    throw permanent("cached package failed its SHA-256 re-check and was removed from the cache");
  }
  d.index.touch(pkg.repoPath);

  if (pkg.kind === "agent") {
    const current = await d.tactical.getAgent(p.agentId);
    if (compareVersions(current.version, pkg.version) >= 0) {
      return { outcome: "ALREADY_INSTALLED", output: `agent already at ${current.version.slice(0, 40)} (target ${pkg.version})` };
    }
  }

  let out: string;
  try {
    out = await d.tactical.runScript(p.agentId, {
      scriptId: d.installScriptId,
      timeoutSec: d.installScriptTimeoutSec,
      envVars: toInstallEnv(pkg, d.cacheBaseUrl),
    });
  } catch (err) {
    // No answer / proxy gateway error / timeout = the script may still be running on the PC. Retrying
    // could start a second installer: report outcome unknown and let PatchGate confirm via inventory.
    if (isRunScriptOutcomeUnknown(err)) {
      const e = err as TacticalError;
      throw outcomeUnknown(`install result unknown (${e.message}${e.detail ? `: ${e.detail}` : ""}); confirm via inventory`);
    }
    throw err;
  }
  const r = parseInstallResult(out);
  if (!r.ok && r.reason === NO_RESULT_LINE) {
    // Tactical answers "timeout" (or nothing usable) when the agent did not finish in time: the
    // installer may have run, or may still be running.
    const tail = clipTail(out.replace(/[^\x20-\x7e]/g, " ").trim(), 200) || "empty output";
    throw outcomeUnknown(`install result unknown (${pkg.wingetId} ${pkg.version}: ${tail}); confirm via inventory`);
  }
  if (!r.ok) {
    const msg = `${pkg.wingetId} ${pkg.version}: ${r.reason}`;
    throw isTransientInstallFailure(r.reason) ? transient(msg) : permanent(msg);
  }
  if (pkg.kind !== "agent") {
    try {
      await d.tactical.refreshSoftware(p.agentId);
    } catch (err) {
      d.log.warn("software inventory refresh failed (non-fatal)", { agentId: p.agentId, err });
    }
  }
  return { outcome: "INSTALLED", output: clipTail(out, 2000) };
}

/** Execute a verified job. Returns a result matching resultSchemas[type]; throws JobError on failure. */
export async function executeJob(type: JobType, payload: unknown, d: ExecutorDeps): Promise<unknown> {
  try {
    return await dispatch(type, payload, d);
  } catch (err) {
    throw toJobError(err);
  }
}

async function dispatch(type: JobType, payload: unknown, d: ExecutorDeps): Promise<unknown> {
  let result: unknown;
  switch (type) {
    case "SYNC_AGENTS":
      result = await syncAgents(d);
      break;
    case "SCAN":
      result = await scan(d, payload as JobPayload<"SCAN">);
      break;
    case "COLLECT":
      result = await collect(d, payload as JobPayload<"COLLECT">);
      break;
    case "DEPLOY_WINDOWS": {
      const p = payload as JobPayload<"DEPLOY_WINDOWS">;
      result = await guarded(d, p.agentId, () => deployWindows(d, p));
      break;
    }
    case "RESET_APPROVALS": {
      const p = payload as JobPayload<"RESET_APPROVALS">;
      result = await guarded(d, p.agentId, () => resetApprovals(d, p));
      break;
    }
    case "CACHE_PACKAGE":
      result = await cachePackage(d, payload as JobPayload<"CACHE_PACKAGE">);
      break;
    case "DEPLOY_PACKAGE":
      result = await deployPackage(d, payload as JobPayload<"DEPLOY_PACKAGE">);
      break;
    case "WU_SCAN":
      result = await wuScan(d, payload as JobPayload<"WU_SCAN">);
      break;
    case "WU_INSTALL":
      result = await wuInstall(d, payload as JobPayload<"WU_INSTALL">);
      break;
    case "TACTICAL_AUDIT_SYNC":
      result = await tacticalAuditSync(d.tactical, payload as JobPayload<"TACTICAL_AUDIT_SYNC">);
      break;
    case "TACTICAL_GUARD_SYNC":
      // Guard off (tactical.guardIntervalSec 0): acknowledged, nothing armed.
      result = d.guard?.enabled ? await d.guard.applySync(payload as JobPayload<"TACTICAL_GUARD_SYNC">) : { allowEntries: 0, known: false };
      break;
    default: {
      const never: never = type;
      throw permanent(`unsupported job type ${String(never)}`);
    }
  }
  const checked = resultSchemas[type].safeParse(result);
  if (!checked.success) throw permanent(`connector produced an invalid ${type} result: ${checked.error.issues[0]?.message ?? "?"}`);
  return checked.data;
}

export const isDeployJob = (t: JobType): boolean => t === "DEPLOY_WINDOWS" || t === "DEPLOY_PACKAGE" || t === "WU_INSTALL";
/**
 * Jobs that must not be blindly re-run after a crash mid-execution: a second run could start a second
 * installer on the PC. WU_INSTALL skips installed KBs, but an interrupted run may still be running
 * wusa/DISM on the PC, so a second concurrent run is not started either. (DEPLOY_WINDOWS is safe to
 * repeat: it re-applies the exact approval state and Windows Update skips what is already installed.)
 */
export const isNonIdempotent = (t: JobType): boolean => t === "DEPLOY_PACKAGE" || t === "WU_INSTALL";

/**
 * Read-only jobs: running them again is always safe. Their (possibly large) result bodies are never
 * written to the journal; a re-delivery after a restart simply runs them again.
 */
export const isReadOnlyJob = (t: string): boolean =>
  t === "SYNC_AGENTS" || t === "SCAN" || t === "COLLECT" || t === "WU_SCAN" || t === "TACTICAL_AUDIT_SYNC" || t === "TACTICAL_GUARD_SYNC";

/** Cache paths a verified job refers to (protected from cache eviction until the job expires). */
export function packagePaths(type: JobType, payload: unknown): string[] {
  switch (type) {
    case "CACHE_PACKAGE":
      return [(payload as JobPayload<"CACHE_PACKAGE">).package.repoPath];
    case "DEPLOY_PACKAGE":
      return [(payload as JobPayload<"DEPLOY_PACKAGE">).package.repoPath];
    case "WU_SCAN":
      return [(payload as JobPayload<"WU_SCAN">).scanCab.repoPath];
    case "WU_INSTALL":
      return (payload as JobPayload<"WU_INSTALL">).updates.flatMap((u) => u.files.map((f) => f.repoPath));
    default:
      return [];
  }
}
