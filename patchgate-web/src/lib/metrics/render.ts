/**
 * OpsSnapshot → Prometheus families. Pure (unit-tested). Label `bank` = Tenant.slug (unique, stable, readable).
 * Ages are exported as seconds; "never" is +Inf so `> threshold` alerts fire for it too.
 * Alert rules: deploy/monitoring/alerts.yml — keep metric names in sync.
 */
import { TACTICAL_HEALTH_STATES } from "@/lib/connector/protocol";
import { Registry } from "./prom";
import { complianceRatio } from "./thresholds";
import type { BankOps, OpsSnapshot, PlatformOps } from "./types";

const P = "patchgate_";
const ts = (d: Date): number => Math.floor(d.getTime() / 1000);
const age = (v: number | null): number => (v === null ? Infinity : v);

function declareBankFamilies(r: Registry): void {
  r.declare(`${P}bank_info`, "Bank (tenant) known to the platform; value 1. Labels: bank slug, name, active.");
  r.declare(`${P}endpoints`, "Endpoints (PCs/servers) per bank.");
  r.declare(`${P}connectors`, "Site connectors per bank by state (online / offline / revoked).");
  r.declare(`${P}connector_up`, "1 when an ACTIVE connector was seen in the last 10 minutes.");
  r.declare(`${P}connector_last_seen_age_seconds`, "Seconds since an ACTIVE connector last called in (+Inf = never).");
  r.declare(`${P}connector_info`, "ACTIVE connector version; value 1.");
  r.declare(`${P}connector_cache_free_bytes`, "Free bytes on the connector's site package cache (last heartbeat).");
  r.declare(`${P}connector_tactical_reachable`, "1 when the connector reached its Tactical server (last heartbeat).");
  r.declare(`${P}connector_tactical_health`, "Site Tactical health from the connector heartbeat: 1 for the current state (ok / natsdown / unreachable).");
  r.declare(`${P}connector_tactical_unhealthy_seconds`, "Seconds the site's Tactical has been natsdown / unreachable (0 = healthy).");
  r.declare(`${P}connector_siem_relay_ok`, "Connector audit relay to the bank SIEM: 1 ok, 0 error (only when configured).");
  r.declare(`${P}jobs_open`, "Open connector jobs by type and status (QUEUED / DELIVERED).");
  r.declare(`${P}jobs_oldest_queued_age_seconds`, "Age of the oldest due QUEUED job per bank (0 = none waiting).");
  r.declare(`${P}jobs_failed_24h`, "Connector jobs FAILED or EXPIRED in the last 24 h, by type and status.");
  r.declare(`${P}jobs_succeeded_24h`, "Connector jobs SUCCEEDED in the last 24 h.");
  r.declare(`${P}deployments_active`, "Deployments not yet finished, by status.");
  r.declare(`${P}deployments_finished_24h`, "Deployments finished in the last 24 h, by status.");
  r.declare(`${P}change_requests_pending_approval`, "Change requests waiting for approval.");
  r.declare(`${P}change_requests_pending_approval_oldest_age_seconds`, "Age of the oldest change request waiting for approval (0 = none).");
  r.declare(`${P}compliance_ratio`, "Share of a bank's PCs that are scanned and miss no live patch (0..1).");
  r.declare(`${P}compliance_endpoints`, "PCs per compliance bucket (up_to_date / needs / critical / not_scanned).");
  r.declare(`${P}endpoints_missing_severity`, "Scanned PCs missing at least one live patch of this severity.");
}

function bankMetrics(r: Registry, b: BankOps): void {
  const bank = b.slug;
  r.gauge(`${P}bank_info`, "", 1, { bank, name: b.name, active: String(b.active) });
  r.gauge(`${P}endpoints`, "", b.endpoints, { bank });
  const online = b.connectors.filter((c) => c.online).length;
  r.gauge(`${P}connectors`, "", online, { bank, state: "online" });
  r.gauge(`${P}connectors`, "", b.connectors.length - online, { bank, state: "offline" });
  r.gauge(`${P}connectors`, "", b.revokedConnectors, { bank, state: "revoked" });
  for (const c of b.connectors) {
    const l = { bank, connector: c.name };
    r.gauge(`${P}connector_up`, "", c.online ? 1 : 0, l);
    r.gauge(`${P}connector_last_seen_age_seconds`, "", age(c.lastSeenAgeSec), l);
    r.gauge(`${P}connector_info`, "", 1, { ...l, version: c.version ?? "unknown" });
    if (c.cacheFreeBytes !== null) r.gauge(`${P}connector_cache_free_bytes`, "", c.cacheFreeBytes, l);
    if (c.tacticalReachable !== null) r.gauge(`${P}connector_tactical_reachable`, "", c.tacticalReachable ? 1 : 0, l);
    if (c.tacticalHealth) {
      for (const state of TACTICAL_HEALTH_STATES) r.gauge(`${P}connector_tactical_health`, "", c.tacticalHealth === state ? 1 : 0, { ...l, state });
      r.gauge(`${P}connector_tactical_unhealthy_seconds`, "", c.tacticalUnhealthySec ?? 0, l);
    }
    if (c.siemConfigured) r.gauge(`${P}connector_siem_relay_ok`, "", c.siemOk ? 1 : 0, l);
  }
  for (const j of b.jobBacklog) r.gauge(`${P}jobs_open`, "", j.count, { bank, type: j.type, status: j.status });
  r.gauge(`${P}jobs_oldest_queued_age_seconds`, "", b.oldestQueuedAgeSec ?? 0, { bank });
  for (const j of b.jobsFailed24h) r.gauge(`${P}jobs_failed_24h`, "", j.count, { bank, type: j.type, status: j.status });
  r.gauge(`${P}jobs_succeeded_24h`, "", b.jobsSucceeded24h, { bank });
  for (const [status, n] of Object.entries(b.deploymentsActive)) r.gauge(`${P}deployments_active`, "", n, { bank, status });
  for (const [status, n] of Object.entries(b.deploymentsFinished24h ?? {})) r.gauge(`${P}deployments_finished_24h`, "", n, { bank, status });
  r.gauge(`${P}change_requests_pending_approval`, "", b.crPendingApproval, { bank });
  r.gauge(`${P}change_requests_pending_approval_oldest_age_seconds`, "", b.crOldestPendingAgeSec ?? 0, { bank });
  const c = b.compliance;
  if (c) {
    const ratio = complianceRatio(c);
    if (ratio !== null) r.gauge(`${P}compliance_ratio`, "", ratio, { bank });
    r.gauge(`${P}compliance_endpoints`, "", c.upToDate, { bank, state: "up_to_date" });
    r.gauge(`${P}compliance_endpoints`, "", c.needs, { bank, state: "needs" });
    r.gauge(`${P}compliance_endpoints`, "", c.critical, { bank, state: "critical" });
    r.gauge(`${P}compliance_endpoints`, "", c.notScanned, { bank, state: "not_scanned" });
    r.gauge(`${P}endpoints_missing_severity`, "", c.critical, { bank, severity: "critical" });
    r.gauge(`${P}endpoints_missing_severity`, "", c.important, { bank, severity: "important" });
  }
  if (b.outbox) {
    for (const o of b.outbox) r.gauge(`${P}notification_outbox`, "Notification outbox rows not yet delivered, by status.", o.count, { bank, status: o.status });
    r.gauge(`${P}notification_outbox_oldest_age_seconds`, "Age of the oldest undelivered notification (0 = none).", b.outboxOldestAgeSec ?? 0, { bank });
  }
}

function platformMetrics(r: Registry, p: PlatformOps, now: Date): void {
  if (p.readiness) {
    r.gauge(`${P}ready`, "Readiness of this instance (same verdict as /api/ready): 1 ready, 0 not ready.", p.readiness.ready ? 1 : 0);
    for (const [check, v] of Object.entries(p.readiness.checks)) {
      if (v !== null) r.gauge(`${P}readiness_check`, "Individual /api/ready checks: 1 ok, 0 failing (unknown checks omitted).", v ? 1 : 0, { check });
    }
  }
  r.declare(`${P}audit_chain_valid`, "Audit hash chain verdict of the incremental verification: 1 intact, 0 BROKEN.");
  for (const c of p.auditChains) {
    r.gauge(`${P}audit_chain_valid`, "", c.valid ? 1 : 0, { chain: c.label });
    r.gauge(`${P}audit_chain_verified_age_seconds`, "Seconds since the chain was last verified.", Math.max(0, (now.getTime() - c.verifiedAt.getTime()) / 1000), { chain: c.label });
  }
  r.gauge(`${P}siem_configured`, "1 when a SIEM export target is configured.", p.siemConfigured ? 1 : 0);
  r.declare(`${P}siem_export_lag_seconds`, "Age of the oldest audit event not yet exported to the SIEM, per chain (0 = up to date).");
  for (const c of p.siemChains) {
    r.gauge(`${P}siem_export_lag_seconds`, "", c.lagSec, { chain: c.label });
    if (c.lastExportAt) r.gauge(`${P}siem_last_export_timestamp_seconds`, "Time of the last export batch carrying events, per chain.", ts(c.lastExportAt), { chain: c.label });
  }
  if (p.repoQuota) {
    const q = p.repoQuota;
    r.gauge(`${P}repo_quota_ok`, "0 when the shared repository is over quota (Windows update downloads paused).", q.ok ? 1 : 0);
    r.gauge(`${P}repo_quota_bytes`, "Shared repository quota (REPO_MAX_GB).", q.quotaBytes);
    if (q.usedBytes !== null) r.gauge(`${P}repo_used_bytes`, "Shared repository usage at the last quota check.", q.usedBytes);
    r.gauge(`${P}repo_quota_measured_timestamp_seconds`, "Time of the last repository quota check.", ts(q.measuredAt));
  }
  r.declare(`${P}fetch_runs_24h`, "Fetch runs in the last 24 h per source family.");
  for (const f of p.fetch) {
    r.gauge(`${P}fetch_runs_24h`, "", f.runs24h, { source: f.source });
    r.gauge(`${P}fetch_runs_failed_24h`, "Failed fetch runs in the last 24 h per source family.", f.failed24h, { source: f.source });
    if (f.lastSuccessAt) r.gauge(`${P}fetch_last_success_timestamp_seconds`, "Time of the last successful fetch run per source family.", ts(f.lastSuccessAt), { source: f.source });
  }
  r.declare(`${P}worker_step_last_success_timestamp_seconds`, "Time a worker tick step last succeeded (step=tick: the whole tick).");
  for (const s of p.workerSteps) {
    const l = { step: s.step };
    r.gauge(`${P}worker_step_last_run_timestamp_seconds`, "Time a worker tick step last ran.", ts(s.lastRunAt), l);
    if (s.lastSuccessAt) r.gauge(`${P}worker_step_last_success_timestamp_seconds`, "", ts(s.lastSuccessAt), l);
    r.gauge(`${P}worker_step_last_ok`, "1 when the step's last run succeeded.", s.lastOk ? 1 : 0, l);
    r.gauge(`${P}worker_step_last_duration_seconds`, "Duration of the step's last run.", s.lastDurationMs / 1000, l);
    r.counter(`${P}worker_step_runs_total`, "Worker step runs (all instances).", s.runs, l);
    r.counter(`${P}worker_step_failures_total`, "Failed worker step runs (all instances).", s.failures, l);
    r.counter(`${P}worker_step_duration_seconds_total`, "Total time spent in the step (all instances).", s.totalDurationMs / 1000, l);
  }
  for (const [kind, n] of Object.entries(p.heldPackages)) r.gauge(`${P}packages_held`, "Downloaded packages waiting for a platform trust decision, by kind.", n, { kind });
  if (p.cert) {
    r.gauge(`${P}tls_cert_probe_ok`, "1 when the PUBLIC_BASE_URL certificate could be read.", p.cert.expiresAt ? 1 : 0, { host: p.cert.host });
    if (p.cert.expiresAt) r.gauge(`${P}tls_cert_expiry_timestamp_seconds`, "notAfter of the certificate served at PUBLIC_BASE_URL.", ts(p.cert.expiresAt), { host: p.cert.host });
  }
}

export function renderMetrics(s: OpsSnapshot): string {
  const r = new Registry();
  declareBankFamilies(r);
  for (const b of s.banks) bankMetrics(r, b);
  platformMetrics(r, s.platform, s.generatedAt);
  r.gauge(`${P}metrics_collect_duration_seconds`, "Time the last refresh of each snapshot tier took.", s.collect.fastMs / 1000, { tier: "fast" });
  r.gauge(`${P}metrics_collect_duration_seconds`, "", s.collect.slowMs / 1000, { tier: "slow" });
  r.gauge(`${P}metrics_snapshot_timestamp_seconds`, "When each snapshot tier was collected.", ts(s.collect.fastAt), { tier: "fast" });
  r.gauge(`${P}metrics_snapshot_timestamp_seconds`, "", ts(s.collect.slowAt), { tier: "slow" });
  r.declare(`${P}metrics_collect_errors`, "Snapshot parts that failed to collect (1 per failing part).");
  for (const part of s.errors) r.gauge(`${P}metrics_collect_errors`, "", 1, { part });
  return r.render();
}
