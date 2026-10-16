import type { AgeBucket } from "./period";

/** Compliance report data model (serialisable: dates become ISO strings in exports and the content hash). */

export interface ReportMeta {
  bankId: string | null;
  bankName: string;
  periodLabel: string;
  from: Date;
  to: Date;
  generatedAt: Date;
  generatedBy: string;
}

export interface RingRow {
  ringId: string | null;
  ring: string;
  endpoints: number;
  scanned: number;
  compliant: number;
  compliancePct: number | null;
}

export interface FleetSummary {
  endpoints: number;
  scanned: number;
  compliant: number;
  /** compliant / scanned (endpoints never scanned are not counted as compliant) */
  compliancePct: number | null;
  criticalMissing: number;
  importantMissing: number;
}

export interface GapRow {
  severity: "CRITICAL" | "IMPORTANT";
  bucket: AgeBucket;
  missing: number;
  endpoints: number;
}

export interface MissingPatchRow {
  patchId: string;
  title: string;
  kb: string | null;
  kind: string;
  severity: string;
  releasedAt: Date | null;
  endpoints: number;
}

export interface AppRow {
  app: string;
  wingetId: string;
  latestVerified: string | null;
  installedVersions: string[];
  endpointsWithApp: number;
  endpointsMissingLatest: number;
}

export interface ChangeRow {
  id: string;
  title: string;
  ticketRef: string | null;
  status: string;
  emergency: boolean;
  emergencyReason: string | null;
  ring: string;
  maker: string;
  approvers: string[];
  createdAt: Date;
  submittedAt: Date | null;
  decidedAt: Date | null;
  completedAt: Date | null;
  targets: number | null;
  succeeded: number;
  failed: number;
}

export interface ExceptionRow {
  kind: "ignored-app" | "held-package";
  name: string;
  detail: string;
  endpoints: number | null;
  since: Date | null;
}

export interface ConnectorRow {
  connector: string;
  status: string;
  lastSeenAt: Date | null;
  outages: number;
  downtimeMinutes: number;
  uptimePct: number | null;
  offlineNow: boolean;
}

export interface EvidenceBlock {
  chain: string;
  headSeq: string | null;
  headHash: string | null;
  headTs: Date | null;
  eventsInPeriod: number;
  lastAnchorSeq: string | null;
  lastAnchorAt: Date | null;
  verified: boolean | null;
  verifiedAt: Date | null;
  fullVerifiedAt: Date | null;
  verifiedThroughSeq: string | null;
  problem: string | null;
  /** The verification checkpoint covers the period's head */
  coversPeriod: boolean;
}

export interface BankReport {
  meta: ReportMeta;
  fleet: FleetSummary;
  rings: RingRow[];
  gaps: GapRow[];
  topMissing: MissingPatchRow[];
  apps: AppRow[];
  changes: ChangeRow[];
  exceptions: ExceptionRow[];
  connectors: ConnectorRow[];
  evidence: EvidenceBlock;
}

export interface BankSummaryRow {
  bankId: string;
  bank: string;
  endpoints: number;
  scanned: number;
  compliancePct: number | null;
  criticalMissing: number;
  importantMissing: number;
  changes: number;
  failedChanges: number;
  emergencyChanges: number;
  connectorsOfflineNow: number;
  auditChainValid: boolean | null;
}

export interface PlatformSummary {
  meta: ReportMeta;
  banks: BankSummaryRow[];
}
