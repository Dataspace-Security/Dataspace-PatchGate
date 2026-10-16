import "server-only";
import { env } from "@/lib/env";
import { readiness } from "@/lib/health";
import { log } from "@/lib/log";
import { withPlatform, type Tx } from "@/lib/tenancy/db";
import { cached } from "./cache";
import {
  ageSec,
  loadActiveDeployments,
  loadCompliance,
  loadConnectors,
  loadFinishedDeployments24h,
  loadJobBacklog,
  loadJobOutcomes24h,
  loadOutbox,
  loadPendingApprovals,
  loadTenants,
  type TenantRow,
} from "./collect-banks";
import { loadAuditChains, loadFetchRuns, loadHeldPackages, loadRepoQuota, loadSiemLag } from "./collect-platform";
import { publicCertStatus } from "./tls";
import { readStepRuns } from "./worker-steps";
import type { BankOps, OpsSnapshot, PlatformOps } from "./types";

/**
 * The operations snapshot behind /api/metrics and /operations. Two refresh tiers, each cached per process
 * with in-flight de-duplication (concurrent scrapes / page loads share one computation):
 *  - fast (15 s): connectors, open job backlog, approvals, audit/SIEM, worker steps, quota, readiness;
 *  - slow (5 min): fleet-wide compliance and 24 h outcome counts (the only scans over large tables).
 * Every part is collected independently: a failing part is reported in `errors` (metric
 * patchgate_metrics_collect_errors) and the rest of the snapshot is still served.
 */

export const FAST_TTL_MS = 15_000;
export const SLOW_TTL_MS = 5 * 60_000;
const TX_TIMEOUT_MS = 120_000;

type Part<T> = { ok: true; value: T } | { ok: false };

async function part<T>(name: string, errors: string[], fn: () => Promise<T>): Promise<Part<T>> {
  try {
    return { ok: true, value: await fn() };
  } catch (err: unknown) {
    errors.push(name);
    log.warn("metrics.collect.part_failed", { part: name, err });
    return { ok: false };
  }
}

function value<T>(p: Part<T>, fallback: T): T {
  return p.ok ? p.value : fallback;
}

/** Each part in its own platform-scoped transaction: one failing query never aborts the others. */
function platformPart<T>(name: string, errors: string[], fn: (tx: Tx) => Promise<T>): Promise<Part<T>> {
  return part(name, errors, () => withPlatform(fn, { timeoutMs: TX_TIMEOUT_MS }));
}

async function collectFast() {
  const now = new Date();
  const t0 = Date.now();
  const errors: string[] = [];
  const tenants = await platformPart("tenants", errors, loadTenants);
  const connectors = await platformPart("connectors", errors, (tx) => loadConnectors(tx, now));
  const jobs = await platformPart("jobs", errors, (tx) => loadJobBacklog(tx, now));
  const deployments = await platformPart("deployments", errors, loadActiveDeployments);
  const approvals = await platformPart("approvals", errors, loadPendingApprovals);
  const outbox = await platformPart("outbox", errors, loadOutbox);
  const tenantMap = new Map(value(tenants, [] as TenantRow[]).map((t) => [t.id, t]));
  const auditChains = await platformPart("auditChains", errors, (tx) => loadAuditChains(tx, tenantMap));
  const siemChains = await platformPart("siem", errors, (tx) => loadSiemLag(tx, tenantMap, now));
  const held = await platformPart("heldPackages", errors, loadHeldPackages);
  const steps = await part("workerSteps", errors, readStepRuns);
  const quota = await part("repoQuota", errors, () => loadRepoQuota(env().REPO_MAX_GB));
  const ready = await part("readiness", errors, readiness);
  const cert = await part("cert", errors, () => publicCertStatus(env().PUBLIC_BASE_URL));
  return { now, ms: Date.now() - t0, errors, tenants, connectors, jobs, deployments, approvals, outbox, auditChains, siemChains, held, steps, quota, ready, cert };
}

async function collectSlow() {
  const now = new Date();
  const t0 = Date.now();
  const errors: string[] = [];
  const compliance = await platformPart("compliance", errors, loadCompliance);
  const outcomes = await platformPart("jobOutcomes", errors, (tx) => loadJobOutcomes24h(tx, now));
  const finished = await platformPart("deploymentsFinished", errors, (tx) => loadFinishedDeployments24h(tx, now));
  const fetchRuns = await platformPart("fetchRuns", errors, (tx) => loadFetchRuns(tx, now));
  return { now, ms: Date.now() - t0, errors, compliance, outcomes, finished, fetchRuns };
}

type Fast = Awaited<ReturnType<typeof collectFast>>;
type Slow = Awaited<ReturnType<typeof collectSlow>>;

function buildBanks(f: Fast, s: Slow): BankOps[] {
  const conns = value(f.connectors, { active: new Map(), revoked: new Map() });
  const jobs = value(f.jobs, { backlog: new Map(), oldestDue: new Map() });
  const deployments = value(f.deployments, new Map<string, Record<string, number>>());
  const approvals = value(f.approvals, new Map<string, { count: number; oldest: Date | null }>());
  const outbox = value(f.outbox, null);
  const compliance = s.compliance.ok ? s.compliance.value : null;
  const outcomes = value(s.outcomes, { failed: new Map(), succeeded: new Map() });
  const finished = s.finished.ok ? s.finished.value : null;
  return value(f.tenants, []).map((t) => {
    const c = compliance?.get(t.id) ?? (compliance ? { total: 0, notScanned: 0, upToDate: 0, needs: 0, critical: 0, important: 0 } : null);
    const cr = approvals.get(t.id);
    return {
      tenantId: t.id,
      slug: t.slug,
      name: t.name,
      active: t.active,
      endpoints: c?.total ?? 0,
      connectors: conns.active.get(t.id) ?? [],
      revokedConnectors: conns.revoked.get(t.id) ?? 0,
      jobBacklog: jobs.backlog.get(t.id) ?? [],
      oldestQueuedAgeSec: ageSec(jobs.oldestDue.get(t.id), f.now),
      jobsFailed24h: outcomes.failed.get(t.id) ?? [],
      jobsSucceeded24h: outcomes.succeeded.get(t.id) ?? 0,
      deploymentsActive: deployments.get(t.id) ?? {},
      deploymentsFinished24h: finished ? (finished.get(t.id) ?? {}) : null,
      crPendingApproval: cr?.count ?? 0,
      crOldestPendingAgeSec: ageSec(cr?.oldest ?? null, f.now),
      compliance: c,
      outbox: outbox ? (outbox.counts.get(t.id) ?? []) : null,
      outboxOldestAgeSec: outbox ? ageSec(outbox.oldest.get(t.id), f.now) : null,
    };
  });
}

function buildPlatform(f: Fast, s: Slow): PlatformOps {
  const ready = f.ready.ok ? f.ready.value : null;
  return {
    auditChains: value(f.auditChains, []),
    siemConfigured: Boolean(env().SIEM_SYSLOG_URL),
    siemChains: value(f.siemChains, []),
    repoQuota: value(f.quota, null),
    fetch: value(s.fetchRuns, []),
    workerSteps: value(f.steps, []),
    heldPackages: value(f.held, {}),
    cert: value(f.cert, null),
    readiness: ready ? { ready: ready.ready, checks: { ...ready.checks } } : null,
  };
}

const fast = cached(collectFast, { ttlMs: FAST_TTL_MS });
const slow = cached(collectSlow, { ttlMs: SLOW_TTL_MS });

/** Cached snapshot (cheap to call on every scrape / page view). */
export async function opsSnapshot(): Promise<OpsSnapshot> {
  const [f, s] = await Promise.all([fast.get(), slow.get()]);
  return {
    generatedAt: f.now,
    collect: { fastMs: f.ms, fastAt: f.now, slowMs: s.ms, slowAt: s.now },
    errors: [...f.errors, ...s.errors],
    banks: buildBanks(f, s),
    platform: buildPlatform(f, s),
  };
}

/** Drop cached tiers (tests, forced refresh). */
export function resetOpsSnapshotCache(): void {
  fast.reset();
  slow.reset();
}
