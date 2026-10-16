/**
 * Red / amber / green rules for the operations dashboard. Pure. The red thresholds match the alert rules in
 * deploy/monitoring/alerts.yml and docs/RUNBOOK.md §8 — change them together.
 */
import type { BankOps, CertOps, ComplianceOps, ConnectorOps, FetchSourceOps, RepoQuotaOps, SiemChainOps, WorkerStepOps } from "./types";

export type Rag = "green" | "amber" | "red" | "none";

const MIN = 60;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;

export const THRESHOLDS = {
  /** a connector unseen this long is offline (connector/policy.ts OFFLINE_AFTER_MS) */
  connectorOfflineSec: 10 * MIN,
  /** oldest due QUEUED job */
  jobQueuedAmberSec: 15 * MIN,
  jobQueuedRedSec: HOUR,
  /** failed share of jobs finished in 24 h */
  jobFailureAmber: 0.05,
  jobFailureRed: 0.1,
  /** change request waiting for approval */
  crWaitingAmberSec: 4 * HOUR,
  crWaitingRedSec: DAY,
  /** share of a bank's PCs that are up to date */
  complianceGreen: 0.95,
  complianceAmber: 0.8,
  siemLagAmberSec: 5 * MIN,
  siemLagRedSec: 15 * MIN,
  repoQuotaAmber: 0.85,
  repoQuotaRed: 0.95,
  certAmberDays: 21,
  certRedDays: 7,
  /** worker step: no success for this long */
  workerStaleAmberSec: 2 * MIN,
  workerStaleRedSec: 5 * MIN,
  /** fetch: no successful run of a source for this long */
  fetchStaleRedSec: 26 * HOUR,
} as const;

const ORDER: Record<Rag, number> = { none: 0, green: 1, amber: 2, red: 3 };

/** The worst of several statuses ("none" only when every input is "none"). */
export function worst(...rags: Rag[]): Rag {
  return rags.reduce<Rag>((w, r) => (ORDER[r] > ORDER[w] ? r : w), "none");
}

export function ragRank(r: Rag): number {
  return ORDER[r];
}

function band(value: number | null, amber: number, red: number): Rag {
  if (value === null) return "green";
  if (value >= red) return "red";
  if (value >= amber) return "amber";
  return "green";
}

export function connectorsRag(connectors: readonly ConnectorOps[]): Rag {
  if (connectors.length === 0) return "none";
  if (connectors.some((c) => !c.online)) return "red";
  if (connectors.some((c) => c.tacticalReachable === false || c.siemOk === false)) return "amber";
  return "green";
}

export function siemRelayRag(connectors: readonly ConnectorOps[]): Rag {
  const reporting = connectors.filter((c) => c.siemConfigured !== null);
  if (reporting.length === 0) return "none";
  if (reporting.some((c) => c.siemConfigured && c.siemOk === false)) return "red";
  if (reporting.some((c) => !c.siemConfigured)) return "amber";
  return "green";
}

export function queuedAgeRag(ageSec: number | null): Rag {
  return band(ageSec, THRESHOLDS.jobQueuedAmberSec, THRESHOLDS.jobQueuedRedSec);
}

/** Failed share of the jobs finished in 24 h; null when nothing finished. */
export function failureRate(failed: number, succeeded: number): number | null {
  const total = failed + succeeded;
  return total === 0 ? null : failed / total;
}

export function failureRag(failed: number, succeeded: number): Rag {
  const rate = failureRate(failed, succeeded);
  if (rate === null) return failed > 0 ? "red" : "green";
  return band(rate, THRESHOLDS.jobFailureAmber, THRESHOLDS.jobFailureRed);
}

export function crWaitingRag(oldestAgeSec: number | null): Rag {
  return band(oldestAgeSec, THRESHOLDS.crWaitingAmberSec, THRESHOLDS.crWaitingRedSec);
}

/** Share of PCs up to date (0..1), null without PCs. */
export function complianceRatio(c: ComplianceOps | null): number | null {
  if (!c || c.total === 0) return null;
  return c.upToDate / c.total;
}

export function complianceRag(c: ComplianceOps | null): Rag {
  const ratio = complianceRatio(c);
  if (ratio === null) return "none";
  if (ratio < THRESHOLDS.complianceAmber) return "red";
  if (ratio < THRESHOLDS.complianceGreen || (c?.critical ?? 0) > 0) return "amber";
  return "green";
}

export function siemLagRag(chains: readonly SiemChainOps[], configured: boolean): Rag {
  if (!configured) return "none";
  const lag = chains.reduce((m, c) => Math.max(m, c.pending ? c.lagSec : 0), 0);
  return band(lag, THRESHOLDS.siemLagAmberSec, THRESHOLDS.siemLagRedSec);
}

export function repoQuotaRag(q: RepoQuotaOps | null): Rag {
  if (!q) return "none";
  if (!q.ok) return "red";
  if (q.usedBytes === null || q.quotaBytes <= 0) return "green";
  return band(q.usedBytes / q.quotaBytes, THRESHOLDS.repoQuotaAmber, THRESHOLDS.repoQuotaRed);
}

export function certRag(c: CertOps | null): Rag {
  if (!c) return "none";
  if (c.daysLeft === null) return "amber"; // probe failed: unknown is worth a look, not a page
  if (c.daysLeft < THRESHOLDS.certRedDays) return "red";
  if (c.daysLeft < THRESHOLDS.certAmberDays) return "amber";
  return "green";
}

export function workerStepRag(s: WorkerStepOps, now: Date): Rag {
  const sinceSuccess = s.lastSuccessAt ? (now.getTime() - s.lastSuccessAt.getTime()) / 1000 : Infinity;
  if (sinceSuccess >= THRESHOLDS.workerStaleRedSec) return "red";
  if (!s.lastOk || sinceSuccess >= THRESHOLDS.workerStaleAmberSec) return "amber";
  return "green";
}

export function fetchRag(f: FetchSourceOps, now: Date): Rag {
  const sinceSuccess = f.lastSuccessAt ? (now.getTime() - f.lastSuccessAt.getTime()) / 1000 : Infinity;
  if (sinceSuccess >= THRESHOLDS.fetchStaleRedSec) return "red";
  return f.failed24h > 0 ? "amber" : "green";
}

export interface BankRag {
  connectors: Rag;
  backlog: Rag;
  failures: Rag;
  approvals: Rag;
  compliance: Rag;
  siemRelay: Rag;
  overall: Rag;
}

export function jobsFailedTotal(b: BankOps): number {
  return b.jobsFailed24h.reduce((n, j) => n + j.count, 0);
}

export function bankRag(b: BankOps): BankRag {
  const r = {
    connectors: connectorsRag(b.connectors),
    backlog: queuedAgeRag(b.oldestQueuedAgeSec),
    failures: failureRag(jobsFailedTotal(b), b.jobsSucceeded24h),
    approvals: crWaitingRag(b.crOldestPendingAgeSec),
    compliance: complianceRag(b.compliance),
    siemRelay: siemRelayRag(b.connectors),
  };
  return { ...r, overall: worst(r.connectors, r.backlog, r.failures, r.approvals, r.compliance, r.siemRelay) };
}
