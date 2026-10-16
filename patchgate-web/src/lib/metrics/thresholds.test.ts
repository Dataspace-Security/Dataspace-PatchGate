import { describe, expect, it } from "vitest";
import {
  bankRag,
  certRag,
  complianceRag,
  connectorsRag,
  crWaitingRag,
  failureRag,
  fetchRag,
  queuedAgeRag,
  repoQuotaRag,
  siemLagRag,
  siemRelayRag,
  workerStepRag,
  worst,
} from "./thresholds";
import { renderMetrics } from "./render";
import type { BankOps, ConnectorOps, OpsSnapshot, WorkerStepOps } from "./types";

const now = new Date("2026-10-16T12:00:00Z");
const ago = (sec: number) => new Date(now.getTime() - sec * 1000);

function conn(over: Partial<ConnectorOps> = {}): ConnectorOps {
  return { id: "c1", name: "HQ", online: true, lastSeenAt: ago(30), lastSeenAgeSec: 30, version: "1.2.0", cacheFreeBytes: 10_000, tacticalReachable: true, siemConfigured: true, siemOk: true, ...over };
}

function bank(over: Partial<BankOps> = {}): BankOps {
  return {
    tenantId: "t1",
    slug: "bank-a",
    name: "Bank A",
    active: true,
    endpoints: 100,
    connectors: [conn()],
    revokedConnectors: 0,
    jobBacklog: [],
    oldestQueuedAgeSec: null,
    jobsFailed24h: [],
    jobsSucceeded24h: 50,
    deploymentsActive: {},
    deploymentsFinished24h: {},
    crPendingApproval: 0,
    crOldestPendingAgeSec: null,
    compliance: { total: 100, notScanned: 0, upToDate: 99, needs: 1, critical: 0, important: 1 },
    outbox: null,
    outboxOldestAgeSec: null,
    ...over,
  };
}

describe("RAG thresholds", () => {
  it("worst() picks the most severe", () => {
    expect(worst("green", "amber", "none")).toBe("amber");
    expect(worst("green", "red", "amber")).toBe("red");
    expect(worst("none")).toBe("none");
    expect(worst()).toBe("none");
  });

  it("connectors: any offline is red, degraded heartbeat amber", () => {
    expect(connectorsRag([])).toBe("none");
    expect(connectorsRag([conn()])).toBe("green");
    expect(connectorsRag([conn(), conn({ online: false })])).toBe("red");
    expect(connectorsRag([conn({ tacticalReachable: false })])).toBe("amber");
  });

  it("SIEM relay from heartbeats", () => {
    expect(siemRelayRag([conn({ siemConfigured: null, siemOk: null })])).toBe("none");
    expect(siemRelayRag([conn()])).toBe("green");
    expect(siemRelayRag([conn({ siemOk: false })])).toBe("red");
    expect(siemRelayRag([conn({ siemConfigured: false, siemOk: false })])).toBe("amber");
  });

  it("job backlog age: amber 15 min, red 1 h", () => {
    expect(queuedAgeRag(null)).toBe("green");
    expect(queuedAgeRag(14 * 60)).toBe("green");
    expect(queuedAgeRag(15 * 60)).toBe("amber");
    expect(queuedAgeRag(3600)).toBe("red");
  });

  it("failure rate: amber 5 %, red 10 %", () => {
    expect(failureRag(0, 0)).toBe("green");
    expect(failureRag(4, 96)).toBe("green");
    expect(failureRag(5, 95)).toBe("amber");
    expect(failureRag(10, 90)).toBe("red");
  });

  it("approval waiting: amber 4 h, red 24 h", () => {
    expect(crWaitingRag(null)).toBe("green");
    expect(crWaitingRag(4 * 3600)).toBe("amber");
    expect(crWaitingRag(24 * 3600)).toBe("red");
  });

  it("compliance: green >= 95 % without critical, red < 80 %", () => {
    expect(complianceRag(null)).toBe("none");
    expect(complianceRag({ total: 0, notScanned: 0, upToDate: 0, needs: 0, critical: 0, important: 0 })).toBe("none");
    expect(complianceRag({ total: 100, notScanned: 0, upToDate: 96, needs: 4, critical: 0, important: 0 })).toBe("green");
    expect(complianceRag({ total: 100, notScanned: 0, upToDate: 96, needs: 3, critical: 1, important: 0 })).toBe("amber");
    expect(complianceRag({ total: 100, notScanned: 10, upToDate: 85, needs: 5, critical: 0, important: 0 })).toBe("amber");
    expect(complianceRag({ total: 100, notScanned: 30, upToDate: 70, needs: 0, critical: 0, important: 0 })).toBe("red");
  });

  it("SIEM export lag only when a SIEM is configured", () => {
    const chain = (lagSec: number, pending = true) => ({ chain: "c", label: "c", lastExportAt: null, lagSec, pending });
    expect(siemLagRag([chain(99_999)], false)).toBe("none");
    expect(siemLagRag([chain(60)], true)).toBe("green");
    expect(siemLagRag([chain(6 * 60)], true)).toBe("amber");
    expect(siemLagRag([chain(16 * 60)], true)).toBe("red");
    expect(siemLagRag([chain(99_999, false)], true)).toBe("green");
  });

  it("repository quota: amber 85 %, red 95 % / exceeded", () => {
    const q = (used: number, ok = true) => ({ ok, usedBytes: used, quotaBytes: 100, measuredAt: now });
    expect(repoQuotaRag(null)).toBe("none");
    expect(repoQuotaRag(q(50))).toBe("green");
    expect(repoQuotaRag(q(86))).toBe("amber");
    expect(repoQuotaRag(q(96))).toBe("red");
    expect(repoQuotaRag(q(10, false))).toBe("red");
  });

  it("certificate: amber < 21 d, red < 7 d, unknown amber", () => {
    const c = (daysLeft: number | null) => ({ host: "h", expiresAt: null, daysLeft, error: null, checkedAt: now });
    expect(certRag(null)).toBe("none");
    expect(certRag(c(60))).toBe("green");
    expect(certRag(c(20))).toBe("amber");
    expect(certRag(c(6))).toBe("red");
    expect(certRag(c(null))).toBe("amber");
  });

  it("worker step: red without success for 5 min", () => {
    const s = (lastSuccessSec: number | null, lastOk = true): WorkerStepOps => ({
      step: "x", lastRunAt: ago(10), lastDurationMs: 5, lastOk, lastStatus: "ok", lastSuccessAt: lastSuccessSec === null ? null : ago(lastSuccessSec), lastFailureAt: null, runs: 1, failures: 0, totalDurationMs: 5,
    });
    expect(workerStepRag(s(30), now)).toBe("green");
    expect(workerStepRag(s(30, false), now)).toBe("amber");
    expect(workerStepRag(s(3 * 60), now)).toBe("amber");
    expect(workerStepRag(s(5 * 60), now)).toBe("red");
    expect(workerStepRag(s(null), now)).toBe("red");
  });

  it("fetch: red without success for 26 h", () => {
    const f = (sec: number | null, failed = 0) => ({ source: "winget", runs24h: 3, failed24h: failed, lastSuccessAt: sec === null ? null : ago(sec), lastFailureAt: null });
    expect(fetchRag(f(3600), now)).toBe("green");
    expect(fetchRag(f(3600, 1), now)).toBe("amber");
    expect(fetchRag(f(27 * 3600), now)).toBe("red");
    expect(fetchRag(f(null), now)).toBe("red");
  });

  it("bank overall is the worst column", () => {
    expect(bankRag(bank()).overall).toBe("green");
    expect(bankRag(bank({ crOldestPendingAgeSec: 25 * 3600, crPendingApproval: 1 })).overall).toBe("red");
  });
});

describe("renderMetrics", () => {
  const snapshot: OpsSnapshot = {
    generatedAt: now,
    collect: { fastMs: 120, fastAt: now, slowMs: 900, slowAt: now },
    errors: ["fetchRuns"],
    banks: [
      bank({
        connectors: [conn(), conn({ id: "c2", name: "DR", online: false, lastSeenAt: null, lastSeenAgeSec: null, version: null, cacheFreeBytes: null, siemConfigured: null, siemOk: null })],
        jobBacklog: [{ type: "COLLECT", status: "QUEUED", count: 7 }],
        oldestQueuedAgeSec: 1800,
        jobsFailed24h: [{ type: "DEPLOY_WINDOWS", status: "FAILED", count: 2 }],
        deploymentsActive: { QUEUED: 4 },
        crPendingApproval: 2,
        crOldestPendingAgeSec: 7200,
        outbox: [{ status: "PENDING", count: 3 }],
        outboxOldestAgeSec: 60,
      }),
    ],
    platform: {
      auditChains: [{ chain: "platform", label: "platform", valid: true, verifiedAt: ago(30), problem: null }, { chain: "t1", label: "bank-a", valid: false, verifiedAt: ago(30), problem: "x" }],
      siemConfigured: true,
      siemChains: [{ chain: "t1", label: "bank-a", lastExportAt: ago(600), lagSec: 1200, pending: true }],
      repoQuota: { ok: true, usedBytes: 50, quotaBytes: 100, measuredAt: ago(60) },
      fetch: [{ source: "winget", runs24h: 10, failed24h: 1, lastSuccessAt: ago(100), lastFailureAt: ago(50) }],
      workerSteps: [{ step: "tick", lastRunAt: ago(20), lastDurationMs: 1500, lastOk: true, lastStatus: "ok", lastSuccessAt: ago(20), lastFailureAt: null, runs: 10, failures: 1, totalDurationMs: 15_000 }],
      heldPackages: { app: 1, tactical: 0 },
      cert: { host: "patchgate.example.com", expiresAt: new Date("2026-12-01T00:00:00Z"), daysLeft: 45, error: null, checkedAt: now },
      readiness: { ready: true, checks: { database: true, siemExport: null } },
    },
  };
  const text = renderMetrics(snapshot);

  it("exports per-bank series with the bank slug label", () => {
    expect(text).toContain('patchgate_endpoints{bank="bank-a"} 100');
    expect(text).toContain('patchgate_connectors{bank="bank-a",state="online"} 1');
    expect(text).toContain('patchgate_connectors{bank="bank-a",state="offline"} 1');
    expect(text).toContain('patchgate_connector_last_seen_age_seconds{bank="bank-a",connector="DR"} +Inf');
    expect(text).toContain('patchgate_connector_info{bank="bank-a",connector="DR",version="unknown"} 1');
    expect(text).toContain('patchgate_jobs_open{bank="bank-a",status="QUEUED",type="COLLECT"} 7');
    expect(text).toContain('patchgate_jobs_oldest_queued_age_seconds{bank="bank-a"} 1800');
    expect(text).toContain('patchgate_jobs_failed_24h{bank="bank-a",status="FAILED",type="DEPLOY_WINDOWS"} 2');
    expect(text).toContain('patchgate_change_requests_pending_approval_oldest_age_seconds{bank="bank-a"} 7200');
    expect(text).toContain('patchgate_compliance_ratio{bank="bank-a"} 0.99');
    expect(text).toContain('patchgate_endpoints_missing_severity{bank="bank-a",severity="important"} 1');
    expect(text).toContain('patchgate_notification_outbox{bank="bank-a",status="PENDING"} 3');
  });

  it("exports platform series", () => {
    expect(text).toContain('patchgate_audit_chain_valid{chain="bank-a"} 0');
    expect(text).toContain('patchgate_siem_export_lag_seconds{chain="bank-a"} 1200');
    expect(text).toContain("patchgate_repo_used_bytes 50");
    expect(text).toContain('patchgate_fetch_runs_failed_24h{source="winget"} 1');
    expect(text).toContain('patchgate_worker_step_runs_total{step="tick"} 10');
    expect(text).toContain('patchgate_worker_step_last_duration_seconds{step="tick"} 1.5');
    expect(text).toContain('patchgate_packages_held{kind="app"} 1');
    expect(text).toContain(`patchgate_tls_cert_expiry_timestamp_seconds{host="patchgate.example.com"} ${Date.parse("2026-12-01T00:00:00Z") / 1000}`);
    expect(text).toContain("patchgate_ready 1");
    expect(text).not.toContain('check="siemExport"');
    expect(text).toContain('patchgate_metrics_collect_errors{part="fetchRuns"} 1');
  });

  it("is valid exposition: every sample line belongs to a declared family", () => {
    const declared = new Set([...text.matchAll(/^# TYPE (\S+) /gm)].map((m) => m[1]));
    for (const line of text.split("\n")) {
      if (!line || line.startsWith("#")) continue;
      expect(line).toMatch(/^[a-zA-Z_:][a-zA-Z0-9_:]*(\{[^}]*\})? \S+$/);
      expect(declared.has(line.split(/[{ ]/)[0])).toBe(true);
    }
  });
});
