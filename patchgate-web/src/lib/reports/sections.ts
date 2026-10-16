import { AGE_BUCKETS } from "./period";
import type { Cell } from "./csv";
import type { BankReport, PlatformSummary } from "./types";

/** CSV sections of a bank report (pure): header + rows. "noncompliant" is streamed separately (export.ts). */

export const BANK_SECTIONS = ["summary", "rings", "gaps", "top-missing", "apps", "changes", "emergency", "exceptions", "connectors", "evidence", "noncompliant"] as const;
export type BankSection = (typeof BANK_SECTIONS)[number];

export const SECTION_LABEL: Record<BankSection, string> = {
  summary: "Summary",
  rings: "Compliance per ring",
  gaps: "Gaps by age",
  "top-missing": "Top missing patches",
  apps: "Third-party apps",
  changes: "Change requests",
  emergency: "Emergency changes",
  exceptions: "Exceptions",
  connectors: "Connector uptime",
  evidence: "Audit evidence",
  noncompliant: "Non-compliant endpoints",
};

export function isBankSection(v: unknown): v is BankSection {
  return typeof v === "string" && (BANK_SECTIONS as readonly string[]).includes(v);
}

export interface SectionTable {
  header: string[];
  rows: Cell[][];
}

const CHANGE_HEADER = ["id", "title", "ticket", "status", "emergency", "emergency_reason", "ring", "maker", "approvers", "created_at", "submitted_at", "decided_at", "completed_at", "targets", "succeeded", "failed"];

export function sectionTable(r: BankReport, section: Exclude<BankSection, "noncompliant">): SectionTable {
  const changeRows = (rows: BankReport["changes"]): Cell[][] =>
    rows.map((c) => [c.id, c.title, c.ticketRef, c.status, c.emergency, c.emergencyReason, c.ring, c.maker, c.approvers, c.createdAt, c.submittedAt, c.decidedAt, c.completedAt, c.targets, c.succeeded, c.failed]);
  switch (section) {
    case "summary":
      return {
        header: ["bank", "period", "from", "to", "generated_at", "generated_by", "endpoints", "scanned", "compliant", "compliance_pct", "critical_missing", "important_missing", "changes", "emergency_changes"],
        rows: [[r.meta.bankName, r.meta.periodLabel, r.meta.from, r.meta.to, r.meta.generatedAt, r.meta.generatedBy, r.fleet.endpoints, r.fleet.scanned, r.fleet.compliant, r.fleet.compliancePct, r.fleet.criticalMissing, r.fleet.importantMissing, r.changes.length, r.changes.filter((c) => c.emergency).length]],
      };
    case "rings":
      return { header: ["ring", "endpoints", "scanned", "compliant", "compliance_pct"], rows: r.rings.map((x) => [x.ring, x.endpoints, x.scanned, x.compliant, x.compliancePct]) };
    case "gaps": {
      const rows: Cell[][] = [];
      for (const sev of ["CRITICAL", "IMPORTANT"] as const) {
        for (const b of AGE_BUCKETS) {
          const g = r.gaps.find((x) => x.severity === sev && x.bucket === b);
          rows.push([sev, b, g?.missing ?? 0, g?.endpoints ?? 0]);
        }
      }
      return { header: ["severity", "age_days", "missing_installs", "endpoints"], rows };
    }
    case "top-missing":
      return { header: ["patch_id", "title", "kb", "kind", "severity", "released_at", "endpoints_missing"], rows: r.topMissing.map((p) => [p.patchId, p.title, p.kb, p.kind, p.severity, p.releasedAt, p.endpoints]) };
    case "apps":
      return { header: ["app", "winget_id", "latest_verified", "installed_versions", "endpoints_with_app", "endpoints_missing_latest"], rows: r.apps.map((a) => [a.app, a.wingetId, a.latestVerified, a.installedVersions, a.endpointsWithApp, a.endpointsMissingLatest]) };
    case "changes":
      return { header: CHANGE_HEADER, rows: changeRows(r.changes) };
    case "emergency":
      return { header: CHANGE_HEADER, rows: changeRows(r.changes.filter((c) => c.emergency)) };
    case "exceptions":
      return { header: ["kind", "name", "detail", "endpoints", "since"], rows: r.exceptions.map((e) => [e.kind, e.name, e.detail, e.endpoints, e.since]) };
    case "connectors":
      return { header: ["connector", "status", "last_seen_at", "outages", "downtime_minutes", "uptime_pct", "offline_now"], rows: r.connectors.map((c) => [c.connector, c.status, c.lastSeenAt, c.outages, c.downtimeMinutes, c.uptimePct, c.offlineNow]) };
    case "evidence": {
      const e = r.evidence;
      return {
        header: ["chain", "head_seq", "head_hash", "head_ts", "events_in_period", "last_siem_anchor_seq", "last_siem_anchor_at", "verified", "verified_at", "full_verified_at", "verified_through_seq", "covers_period", "problem"],
        rows: [[e.chain, e.headSeq, e.headHash, e.headTs, e.eventsInPeriod, e.lastAnchorSeq, e.lastAnchorAt, e.verified, e.verifiedAt, e.fullVerifiedAt, e.verifiedThroughSeq, e.coversPeriod, e.problem]],
      };
    }
  }
}

export function summaryTable(s: PlatformSummary): SectionTable {
  return {
    header: ["bank", "endpoints", "scanned", "compliance_pct", "critical_missing", "important_missing", "changes", "failed_changes", "emergency_changes", "connectors_offline_now", "audit_chain_valid"],
    rows: s.banks.map((b) => [b.bank, b.endpoints, b.scanned, b.compliancePct, b.criticalMissing, b.importantMissing, b.changes, b.failedChanges, b.emergencyChanges, b.connectorsOfflineNow, b.auditChainValid]),
  };
}
