/** Operations snapshot: one aggregated picture of every bank + the platform (metrics and /operations). */

export interface ConnectorOps {
  id: string;
  name: string;
  /** ACTIVE connectors only are listed (revoked ones are counted per bank). */
  online: boolean;
  lastSeenAt: Date | null;
  /** null = never seen */
  lastSeenAgeSec: number | null;
  version: string | null;
  cacheFreeBytes: number | null;
  tacticalReachable: boolean | null;
  /** Connector → bank SIEM relay: null = no heartbeat / not reported, false = configured with an error */
  siemConfigured: boolean | null;
  siemOk: boolean | null;
}

export interface JobCount {
  type: string;
  status: string;
  count: number;
}

export interface ComplianceOps {
  total: number;
  notScanned: number;
  upToDate: number;
  /** scanned, missing at least one live patch, none critical */
  needs: number;
  /** scanned, missing at least one critical patch */
  critical: number;
  /** scanned, missing at least one important patch (may overlap critical) */
  important: number;
}

export interface OutboxCount {
  status: string;
  count: number;
}

export interface BankOps {
  tenantId: string;
  slug: string;
  name: string;
  active: boolean;
  endpoints: number;
  connectors: ConnectorOps[];
  revokedConnectors: number;
  /** QUEUED / DELIVERED jobs by type */
  jobBacklog: JobCount[];
  /** Due (notBefore passed) QUEUED jobs: age of the oldest, from max(createdAt, notBefore) */
  oldestQueuedAgeSec: number | null;
  /** FAILED / EXPIRED jobs completed in the last 24 h, by type + status */
  jobsFailed24h: JobCount[];
  jobsSucceeded24h: number;
  /** Non-terminal deployments by status */
  deploymentsActive: Record<string, number>;
  /** Deployments finished in the last 24 h by status (heavier query, refreshed less often) */
  deploymentsFinished24h: Record<string, number> | null;
  crPendingApproval: number;
  crOldestPendingAgeSec: number | null;
  compliance: ComplianceOps | null;
  /** null = the notification outbox table does not exist (feature-detected) */
  outbox: OutboxCount[] | null;
  outboxOldestAgeSec: number | null;
}

export interface AuditChainOps {
  chain: string;
  /** bank slug, or "platform" */
  label: string;
  valid: boolean;
  verifiedAt: Date;
  problem: string | null;
}

export interface SiemChainOps {
  chain: string;
  label: string;
  lastExportAt: Date | null;
  /** Age of the oldest event not yet exported (0 = nothing pending) */
  lagSec: number;
  pending: boolean;
}

export interface FetchSourceOps {
  /** source family: "winget", "tactical", "wsusscn2", … */
  source: string;
  runs24h: number;
  failed24h: number;
  lastSuccessAt: Date | null;
  lastFailureAt: Date | null;
}

export interface WorkerStepOps {
  step: string;
  lastRunAt: Date;
  lastDurationMs: number;
  lastOk: boolean;
  lastStatus: string;
  lastSuccessAt: Date | null;
  lastFailureAt: Date | null;
  runs: number;
  failures: number;
  totalDurationMs: number;
}

export interface CertOps {
  host: string;
  expiresAt: Date | null;
  daysLeft: number | null;
  /** short reason when the probe failed */
  error: string | null;
  checkedAt: Date;
}

export interface RepoQuotaOps {
  ok: boolean;
  usedBytes: number | null;
  quotaBytes: number;
  measuredAt: Date;
}

export interface PlatformOps {
  auditChains: AuditChainOps[];
  siemConfigured: boolean;
  siemChains: SiemChainOps[];
  repoQuota: RepoQuotaOps | null;
  fetch: FetchSourceOps[];
  workerSteps: WorkerStepOps[];
  heldPackages: Record<string, number>;
  cert: CertOps | null;
  readiness: { ready: boolean; checks: Record<string, boolean | null> } | null;
}

export interface OpsSnapshot {
  generatedAt: Date;
  /** How long each refresh tier took, and when it ran */
  collect: { fastMs: number; fastAt: Date; slowMs: number; slowAt: Date };
  /** Parts that failed to collect this round (shown + exported as a metric; never the error text) */
  errors: string[];
  banks: BankOps[];
  platform: PlatformOps;
}
