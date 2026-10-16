import "server-only";
import type { Tx } from "@/lib/tenancy";
import { enqueueJob } from "@/lib/connector/queue";
import { jobPackageSchema, type JobPackage } from "@/lib/connector/protocol";
import { AGENT_ARCHES, agentReleaseToPackage, pickAgentRelease } from "@/lib/thirdparty/package-from-db";
import { packageInputSchema } from "@/lib/thirdparty/package-input";

/**
 * Per-connector package cache state, derived from CACHE_PACKAGE jobs (one site downloads a package ONCE
 * from PatchGate; thousands of PCs then pull it from the site cache — ARCHITECTURE-HOSTED §2A):
 *   cached  — newest CACHE_PACKAGE for (connector, sha256) succeeded and its result was applied
 *   pending — a CACHE_PACKAGE job is queued / running / its result is being applied, OR the last attempt
 *             failed and another one is due after CACHE_RETRY_AFTER_MS (deployments wait, they do not fail)
 *   failed  — MAX_CACHE_FAILURES attempts in a row failed: deployments needing the package fail (kind CACHE,
 *             not counted for ring stop). A fresh attempt is made after FAILED_RETRY_AFTER_MS.
 * There is at most one live CACHE_PACKAGE job per connector and package, never one per PC.
 *
 * Scale: the pump builds ONE CacheView per connector per run (one indexed query over that connector's
 * CACHE_PACKAGE jobs) instead of a JSON-path lookup per package per deployment.
 */

export const CACHE_JOB_TTL_MS = 24 * 60 * 60_000;
/** Consecutive failed attempts before deployments needing the package are failed. */
export const MAX_CACHE_FAILURES = 3;
/** Pause between attempts while under the cap. */
export const CACHE_RETRY_AFTER_MS = 30 * 60_000;
/** After the cap: a new attempt (for new / remaining deployments) only after this. */
export const FAILED_RETRY_AFTER_MS = 6 * 60 * 60_000;

export type CacheState = { state: "cached" } | { state: "pending"; jobId: string | null } | { state: "failed"; error: string };

interface CacheJobRow {
  id: string;
  sha256: string | null;
  status: string;
  processedAt: Date | null;
  completedAt: Date | null;
  error: string | null;
}

interface Derived {
  /** null = no usable history: start a download */
  state: CacheState | null;
  /** when the next attempt may be queued (failed history only) */
  retryAt: Date | null;
}

/** Pure: cache state of one package from its jobs, newest first. */
export function deriveCacheState(jobs: readonly CacheJobRow[]): Derived {
  const last = jobs[0];
  if (!last) return { state: null, retryAt: null };
  switch (last.status) {
    case "QUEUED":
    case "DELIVERED":
      return { state: { state: "pending", jobId: last.id }, retryAt: null };
    case "SUCCEEDED":
      return { state: last.processedAt ? { state: "cached" } : { state: "pending", jobId: last.id }, retryAt: null };
    case "FAILED": {
      if (!last.processedAt) return { state: { state: "pending", jobId: last.id }, retryAt: null };
      let failures = 0;
      for (const j of jobs) {
        if (j.status === "FAILED") failures++;
        else if (j.status === "SUCCEEDED") break;
      }
      const at = (last.completedAt ?? new Date(0)).getTime();
      if (failures >= MAX_CACHE_FAILURES) {
        return { state: { state: "failed", error: last.error ?? "caching failed" }, retryAt: new Date(at + FAILED_RETRY_AFTER_MS) };
      }
      return { state: { state: "pending", jobId: null }, retryAt: new Date(at + CACHE_RETRY_AFTER_MS) };
    }
    default: // EXPIRED / CANCELLED: start over
      return { state: null, retryAt: null };
  }
}

/** All CACHE_PACKAGE history of one connector, grouped by package (loaded once per pump run). */
export class CacheView {
  private constructor(private readonly byPackage: Map<string, CacheJobRow[]>) {}

  static async load(tx: Tx, connectorId: string): Promise<CacheView> {
    const rows = await tx.$queryRaw<CacheJobRow[]>`
      SELECT "id", ("payload" -> 'package' ->> 'sha256') AS "sha256", "status"::text AS "status", "processedAt", "completedAt", "error"
        FROM "ConnectorJob"
       WHERE "connectorId" = ${connectorId} AND "type" = 'CACHE_PACKAGE'
       ORDER BY "createdAt" DESC`;
    const by = new Map<string, CacheJobRow[]>();
    for (const r of rows) {
      if (!r.sha256) continue;
      const list = by.get(r.sha256) ?? [];
      list.push(r);
      by.set(r.sha256, list);
    }
    return new CacheView(by);
  }

  derive(sha256: string): Derived {
    return deriveCacheState(this.byPackage.get(sha256) ?? []);
  }

  /** Record a job queued in this run (newest first). */
  noteQueued(sha256: string, jobId: string): void {
    const list = this.byPackage.get(sha256) ?? [];
    this.byPackage.set(sha256, [{ id: jobId, sha256, status: "QUEUED", processedAt: null, completedAt: null, error: null }, ...list]);
  }
}

/** Cache state of one package (single lookup; the pump uses CacheView instead). */
export async function cacheStateOf(tx: Tx, connectorId: string, sha256: string): Promise<{ state: CacheState; completedAt: Date | null } | null> {
  const rows = await tx.$queryRaw<(CacheJobRow & { completedAt: Date | null })[]>`
    SELECT "id", ("payload" -> 'package' ->> 'sha256') AS "sha256", "status"::text AS "status", "processedAt", "completedAt", "error"
      FROM "ConnectorJob"
     WHERE "connectorId" = ${connectorId} AND "type" = 'CACHE_PACKAGE' AND ("payload" -> 'package' ->> 'sha256') = ${sha256}
     ORDER BY "createdAt" DESC
     LIMIT ${MAX_CACHE_FAILURES + 1}`;
  const d = deriveCacheState(rows);
  return d.state ? { state: d.state, completedAt: rows[0]?.completedAt ?? null } : null;
}

/**
 * Make sure the site cache holds `pkg` (or is fetching it). Runs inside withTenant(connector bank).
 * With a CacheView (pump), the history comes from the view; a new job is queued only after re-checking
 * under the per-(connector, package) lock, so concurrent producers never queue two downloads.
 */
export async function ensurePackageCached(tx: Tx, connector: { id: string; tenantId: string }, pkg: JobPackage, now: Date, view?: CacheView): Promise<CacheState> {
  const decide = (d: Derived): CacheState | "enqueue" => {
    if (!d.state) return "enqueue";
    if (d.retryAt && now >= d.retryAt) return "enqueue";
    return d.state;
  };
  if (view) {
    const quick = decide(view.derive(pkg.sha256));
    if (quick !== "enqueue") return quick;
  }
  // Serialise per (connector, package): concurrent producers must not queue two downloads.
  await tx.$executeRaw`SELECT pg_advisory_xact_lock(4242003, hashtext(${`cache:${connector.id}:${pkg.sha256}`}))`;
  const rows = await tx.$queryRaw<CacheJobRow[]>`
    SELECT "id", ("payload" -> 'package' ->> 'sha256') AS "sha256", "status"::text AS "status", "processedAt", "completedAt", "error"
      FROM "ConnectorJob"
     WHERE "connectorId" = ${connector.id} AND "type" = 'CACHE_PACKAGE' AND ("payload" -> 'package' ->> 'sha256') = ${pkg.sha256}
     ORDER BY "createdAt" DESC
     LIMIT ${MAX_CACHE_FAILURES + 1}`;
  const fresh = decide(deriveCacheState(rows));
  if (fresh !== "enqueue") return fresh;
  const job = await enqueueJob(
    tx,
    { tenantId: connector.tenantId, connectorId: connector.id, type: "CACHE_PACKAGE", payload: { package: pkg }, expiresAt: new Date(now.getTime() + CACHE_JOB_TTL_MS) },
    now,
  );
  view?.noteQueued(pkg.sha256, job.id);
  return { state: "pending", jobId: job.id };
}

// ---------------------------------------------------------------------------------------------
// Current Tactical agent builds for a new site cache (after enrolment, installers/site/web-install.md)
// ---------------------------------------------------------------------------------------------

export interface AgentBuildRow {
  version: string;
  assetName: string;
  sha256: string;
  repoPath: string;
  sizeBytes: bigint | number;
}

const AGENT_VERSION_RE = /^\d+\.\d+\.\d+$/;

function compareVersions(a: string, b: string): number {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < 3; i++) if (pa[i] !== pb[i]) return pa[i] - pb[i];
  return 0;
}

/**
 * Pure: the newest VERIFIED agent version's builds, one per Windows architecture (amd64, 386) as job
 * packages. Rows that fail the install-script allow-list are skipped (never queued).
 */
export function currentAgentBuildPackages(rows: readonly AgentBuildRow[]): JobPackage[] {
  const versions = [...new Set(rows.map((r) => r.version).filter((v) => AGENT_VERSION_RE.test(v)))].sort(compareVersions);
  const newest = versions.at(-1);
  if (!newest) return [];
  const builds = rows.filter((r) => r.version === newest);
  const out: JobPackage[] = [];
  for (const arch of AGENT_ARCHES) {
    const r = pickAgentRelease(builds, arch);
    if (!r) continue;
    const input = packageInputSchema.safeParse(agentReleaseToPackage(r));
    if (!input.success) continue;
    const pkg = jobPackageSchema.safeParse({ ...input.data, size: Number(r.sizeBytes) });
    if (pkg.success && !out.some((p) => p.sha256 === pkg.data.sha256)) out.push(pkg.data);
  }
  return out;
}

/**
 * Queue CACHE_PACKAGE for the current VERIFIED Tactical agent build(s) at one connector, so PCs can take the
 * agent from the site cache (Install-PatchGateAgent.ps1 falls back to the bundle's copy until then).
 * Idempotent: ensurePackageCached never queues a second live download. Runs inside withTenant(connector bank).
 */
export async function cacheCurrentAgentBuilds(tx: Tx, connector: { id: string; tenantId: string }, now = new Date()): Promise<{ sha256: string; state: CacheState["state"] }[]> {
  const rows = await tx.mirroredRelease.findMany({
    where: { component: "TACTICAL_AGENT", verification: "VERIFIED" },
    select: { version: true, assetName: true, sha256: true, repoPath: true, sizeBytes: true },
  });
  const out: { sha256: string; state: CacheState["state"] }[] = [];
  for (const pkg of currentAgentBuildPackages(rows)) {
    const st = await ensurePackageCached(tx, connector, pkg, now);
    out.push({ sha256: pkg.sha256, state: st.state });
  }
  return out;
}
