/**
 * Plain-language building blocks of the "patch story" screens (dashboard, PC page, patch page, change request
 * progress). PURE: no I/O, no framework imports — every label and every number rule is unit-tested
 * (story.test.ts) and shared by the page data functions in this folder.
 */
import { CronExpressionParser } from "cron-parser";
import { TACTICAL_MESSAGING_DOWN_NOTE } from "@/lib/connector/policy";

export type Severity = "CRITICAL" | "IMPORTANT" | "MODERATE" | "LOW" | "UNSPECIFIED";
export type Tone = "neutral" | "info" | "warn" | "good" | "bad" | "busy";

export const SEVERITY_LABEL: Record<Severity, string> = {
  CRITICAL: "Critical",
  IMPORTANT: "Important",
  MODERATE: "Moderate",
  LOW: "Low",
  UNSPECIFIED: "Not rated",
};

/** How much one missing patch weighs when ranking "what to fix first" (PCs × weight). */
export const SEVERITY_WEIGHT: Record<Severity, number> = { CRITICAL: 8, IMPORTANT: 4, MODERATE: 2, LOW: 1, UNSPECIFIED: 1 };

export const SEVERITY_TONE: Record<Severity, Tone> = { CRITICAL: "bad", IMPORTANT: "warn", MODERATE: "info", LOW: "neutral", UNSPECIFIED: "neutral" };

/** A PC that has not reported for this long is "not scanned recently". */
export const STALE_SCAN_MS = 24 * 60 * 60_000;

// ---------------------------------------------------------------------------------------------
// Numbers
// ---------------------------------------------------------------------------------------------

export function fmtNum(n: number): string {
  return n.toLocaleString("en-US");
}

/** "7 of 10" — the only way counts are shown, so a number is never read without its total. */
export function ofN(x: number, n: number): string {
  return `${fmtNum(x)} of ${fmtNum(n)}`;
}

/** Whole percent, never 100 % unless everything is (and never 0 % when something is). null when n = 0. */
export function pct(x: number, n: number): number | null {
  if (n <= 0) return null;
  if (x <= 0) return 0;
  if (x >= n) return 100;
  return Math.min(99, Math.max(1, Math.round((x / n) * 100)));
}

export function plural(n: number, one: string, many = `${one}s`): string {
  return `${fmtNum(n)} ${n === 1 ? one : many}`;
}

/** "just now", "5 min ago", "3 h ago", "2 days ago"; "never" for null. Future dates read "in …". */
export function fmtAgo(d: Date | null | undefined, now: Date): string {
  if (!d) return "never";
  const ms = now.getTime() - d.getTime();
  const future = ms < 0;
  const abs = Math.abs(ms);
  const min = Math.floor(abs / 60_000);
  let text: string;
  if (min < 1) return future ? "in under a minute" : "just now";
  if (min < 60) text = `${min} min`;
  else if (min < 48 * 60) text = `${Math.floor(min / 60)} h`;
  else text = `${Math.floor(min / (24 * 60))} days`;
  return future ? `in ${text}` : `${text} ago`;
}

/** First instant of the current calendar month (UTC) — "confirmed this month". */
export function startOfMonthUtc(now: Date): Date {
  return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1));
}

// ---------------------------------------------------------------------------------------------
// PC compliance
// ---------------------------------------------------------------------------------------------

export type PcStatus = { kind: "unscanned" } | { kind: "uptodate" } | { kind: "needs"; missing: number; critical: number };

/** A PC is up to date when it has reported and no live, visible patch is missing on it. */
export function pcStatus(input: { lastScanAt: Date | null; missing: number; critical: number }): PcStatus {
  if (!input.lastScanAt) return { kind: "unscanned" };
  if (input.missing <= 0) return { kind: "uptodate" };
  return { kind: "needs", missing: input.missing, critical: Math.min(input.critical, input.missing) };
}

export function pcStatusLabel(s: PcStatus): { label: string; tone: Tone } {
  switch (s.kind) {
    case "unscanned":
      return { label: "Not scanned yet", tone: "neutral" };
    case "uptodate":
      return { label: "Up to date", tone: "good" };
    case "needs":
      return s.critical > 0 ? { label: `Needs ${fmtNum(s.missing)} · ${fmtNum(s.critical)} critical`, tone: "bad" } : { label: `Needs ${fmtNum(s.missing)}`, tone: "warn" };
  }
}

/** Per-ring (or whole-bank) compliance buckets; every PC is in exactly one. */
export interface ComplianceBuckets {
  total: number;
  notScanned: number;
  upToDate: number;
  /** scanned, missing patches, none critical */
  needs: number;
  /** scanned, missing at least one critical patch */
  critical: number;
}

export function addBuckets(a: ComplianceBuckets, b: ComplianceBuckets): ComplianceBuckets {
  return { total: a.total + b.total, notScanned: a.notScanned + b.notScanned, upToDate: a.upToDate + b.upToDate, needs: a.needs + b.needs, critical: a.critical + b.critical };
}

export const EMPTY_BUCKETS: ComplianceBuckets = { total: 0, notScanned: 0, upToDate: 0, needs: 0, critical: 0 };

/** Installed versions of a managed app on one PC (inventory names matched like the ingest: regex, case-insensitive). */
export function installedVersionsFor(items: readonly { name: string; version: string | null }[], inventoryMatch: string): string[] {
  let re: RegExp;
  try {
    re = new RegExp(inventoryMatch, "i");
  } catch {
    return [];
  }
  return [...new Set(items.filter((i) => re.test(i.name)).map((i) => i.version || "unknown version"))];
}

// ---------------------------------------------------------------------------------------------
// "What to fix first"
// ---------------------------------------------------------------------------------------------

export interface MissingPatchRow {
  patchId: string;
  pcs: number;
  severity: Severity;
}

/** Most important first: PCs × severity weight, then more PCs, then id (stable). */
export function rankMissingPatches<T extends MissingPatchRow>(rows: readonly T[]): T[] {
  const score = (r: MissingPatchRow) => r.pcs * SEVERITY_WEIGHT[r.severity];
  return [...rows].sort((a, b) => score(b) - score(a) || b.pcs - a.pcs || a.patchId.localeCompare(b.patchId));
}

export interface AttentionItem {
  key: string;
  /** lower = more important */
  priority: number;
  text: string;
  hint?: string;
  href: string;
  tone: Tone;
}

export const MAX_ATTENTION_ITEMS = 6;

/** The few things worth doing next, most important first (stable for equal priorities). */
export function pickAttention(items: readonly (AttentionItem | null | false | undefined)[], max = MAX_ATTENTION_ITEMS): AttentionItem[] {
  return items
    .filter((i): i is AttentionItem => Boolean(i))
    .map((item, idx) => ({ item, idx }))
    .sort((a, b) => a.item.priority - b.item.priority || a.idx - b.idx)
    .slice(0, max)
    .map((x) => x.item);
}

// ---------------------------------------------------------------------------------------------
// Deployment progress (per PC of a change request)
// ---------------------------------------------------------------------------------------------

export type DeploymentStatus = "QUEUED" | "SENDING" | "SENT" | "SUCCEEDED" | "FAILED" | "TIMED_OUT";
export type FailureKind = "INSTALL" | "PLANNING" | "CACHE" | "RING_STOPPED" | "DEADLINE" | "UNMANAGED" | "INTERNAL";
export type JobStatus = "QUEUED" | "DELIVERED" | "SUCCEEDED" | "FAILED" | "EXPIRED" | "CANCELLED";

export interface StageInput {
  status: DeploymentStatus;
  note: string | null;
  error: string | null;
  failureKind: FailureKind | null;
  /** change request has a maintenance window: is it open now? null = no window (deploys any time) */
  windowOpen: boolean | null;
  /** next window start (for the waiting text) */
  nextWindowAt?: Date | null;
  /** the PC's site connector: null = no connector manages the PC */
  connectorOnline: boolean | null;
  /** latest install job of this deployment (DEPLOY_* / WU_INSTALL) */
  job: { status: JobStatus; notBefore: Date } | null;
  now: Date;
}

export type StageKey =
  | "waiting-window"
  | "waiting-connector"
  | "caching"
  | "waiting-files"
  | "busy"
  | "queued"
  | "scheduled"
  | "sent-to-site"
  | "installing"
  | "retrying"
  | "tactical-down"
  | "preparing"
  | "awaiting-confirmation"
  | "outcome-unknown"
  | "confirmed"
  | "nothing-to-do"
  | "failed"
  | "not-started"
  | "timed-out";

export interface Stage {
  key: StageKey;
  label: string;
  /** one more sentence (reason, next step) */
  detail: string | null;
  tone: Tone;
  done: boolean;
}

const REASON_MAX = 180;
const short = (s: string | null | undefined) => {
  const t = (s ?? "").replace(/\s+/g, " ").trim();
  return t.length > REASON_MAX ? `${t.slice(0, REASON_MAX - 1)}…` : t;
};

const stage = (key: StageKey, label: string, tone: Tone, detail: string | null = null, done = false): Stage => ({ key, label, tone, detail, done });

function failedStage(input: StageInput): Stage {
  const reason = short(input.error ?? input.note) || "no reason recorded";
  switch (input.failureKind) {
    case "RING_STOPPED":
      return stage("not-started", "Not started: rollout stopped", "bad", "Too many PCs in this ring failed, so the rest were held back to protect the bank.", true);
    case "DEADLINE":
      return stage("not-started", "Not started: deadline passed", "bad", reason, true);
    case "UNMANAGED":
      return stage("failed", "Failed: no connector manages this PC", "bad", "The PC is no longer reported by any active site connector.", true);
    case "PLANNING":
      return stage("failed", `Failed: cannot be delivered to this PC`, "bad", reason, true);
    case "CACHE":
      return stage("failed", "Failed: bank site cache could not get the package", "bad", reason, true);
    case "INTERNAL":
      return stage("failed", "Failed: PatchGate could not prepare the install", "bad", reason, true);
    default:
      return stage("failed", `Failed: ${reason}`, "bad", null, true);
  }
}

function queuedStage(input: StageInput): Stage {
  const note = input.note ?? "";
  if (input.connectorOnline === null) return stage("waiting-connector", "Waiting for a site connector", "warn", "No active site connector manages this PC yet.");
  if (input.connectorOnline === false) return stage("waiting-connector", "Waiting: site connector offline", "warn", "Work resumes when the bank's connector reconnects.");
  if (note.startsWith("waiting for the site cache")) return stage("caching", "Downloading to bank (site cache)", "busy", "The package is copied to the bank once; PCs install from there.");
  if (note.startsWith("waiting for Windows update files")) return stage("waiting-files", "Waiting for Microsoft files", "busy", short(note.replace(/^waiting for Windows update files:\s*/, "")) || null);
  if (note.startsWith("endpoint busy")) return stage("busy", "Waiting: PC busy with another change request", "neutral");
  if (input.windowOpen === false) {
    const next = input.nextWindowAt ? `Next window starts ${fmtAgo(input.nextWindowAt, input.now)}.` : null;
    return stage("waiting-window", "Waiting for maintenance window", "neutral", next);
  }
  return stage("queued", "Queued", "neutral", short(note) || "Picked up by PatchGate's next deployment run.");
}

function sendingStage(input: StageInput): Stage {
  const note = input.note ?? "";
  if (note.startsWith("waiting for the site cache")) return stage("caching", "Downloading to bank (site cache)", "busy", "The package is copied to the bank once; PCs install from there.");
  if (note.startsWith("waiting for Windows update files")) return stage("waiting-files", "Waiting for Microsoft files", "busy", short(note.replace(/^waiting for Windows update files:\s*/, "")) || null);
  const natsDown = note.startsWith(TACTICAL_MESSAGING_DOWN_NOTE) ? /\(retry (\d+) scheduled\)/.exec(note) : null;
  if (natsDown) {
    return stage("tactical-down", "Waiting: Tactical messaging down at the site", "warn", `Retrying automatically (attempt ${Number(natsDown[1]) + 1}); the site's watchdog restarts Tactical's message bus within minutes.`);
  }
  const retry = /^retry (\d+) scheduled after: ([\s\S]*)$/.exec(note);
  if (retry) return stage("retrying", `Retrying (attempt ${Number(retry[1]) + 1})`, "warn", `Last try: ${short(retry[2])}`);
  if (input.job?.status === "DELIVERED") return stage("installing", "Installing", "busy", "The bank's connector is running the install on the PC.");
  if (input.job?.status === "QUEUED") {
    if (input.connectorOnline === false) return stage("waiting-connector", "Waiting: site connector offline", "warn", "Work resumes when the bank's connector reconnects.");
    return input.job.notBefore > input.now
      ? stage("scheduled", "Scheduled", "busy", `Starts ${fmtAgo(input.job.notBefore, input.now)} (installs are spread out to protect the bank network).`)
      : stage("sent-to-site", "Sent to the bank, waiting to start", "busy", "The bank's connector picks it up on its next poll.");
  }
  if (input.windowOpen === false) return stage("waiting-window", "Waiting for maintenance window", "neutral");
  return stage("preparing", "Preparing", "busy", short(note) || null);
}

/** Map one deployment (+ its latest job) to what an operator needs to know, in plain words. */
export function deploymentStage(input: StageInput): Stage {
  switch (input.status) {
    case "QUEUED":
      return queuedStage(input);
    case "SENDING":
      return sendingStage(input);
    case "SENT":
      if ((input.note ?? "").startsWith("nothing to install")) return stage("awaiting-confirmation", "Nothing to install — confirming", "info", "Waiting for the next inventory report from the PC.");
      if ((input.note ?? "").includes("outcome unknown"))
        return stage("outcome-unknown", "Install result unknown — awaiting confirmation", "warn", "PatchGate confirms from the PC's next inventory instead of installing twice.");
      return stage("awaiting-confirmation", "Installed — awaiting confirmation", "info", "Confirmed when the PC's next inventory shows the new version (within 6 h).");
    case "SUCCEEDED":
      if ((input.note ?? "").startsWith("nothing to install")) return stage("nothing-to-do", "Already up to date ✓", "good", null, true);
      return stage("confirmed", "Installed ✓ (confirmed)", "good", "Confirmed by the PC's own inventory.", true);
    case "TIMED_OUT":
      if (input.failureKind === "DEADLINE") return stage("not-started", "Not started: deadline passed", "bad", short(input.error ?? input.note) || null, true);
      return stage("timed-out", "Timed out", "bad", short(input.error) || "The install was not confirmed by the PC's inventory in time.", true);
    case "FAILED":
      return failedStage(input);
  }
}

export interface CrProgress {
  total: number;
  /** finished one way or the other */
  done: number;
  confirmed: number;
  awaitingConfirmation: number;
  inProgress: number;
  waiting: number;
  failed: number;
}

/** Per-status counts of a change request's deployments → the progress bar. */
export function crProgress(counts: Partial<Record<DeploymentStatus, number>>): CrProgress {
  const n = (s: DeploymentStatus) => counts[s] ?? 0;
  const confirmed = n("SUCCEEDED");
  const failed = n("FAILED") + n("TIMED_OUT");
  return {
    total: confirmed + failed + n("SENT") + n("SENDING") + n("QUEUED"),
    done: confirmed + failed,
    confirmed,
    awaitingConfirmation: n("SENT"),
    inProgress: n("SENDING"),
    waiting: n("QUEUED"),
    failed,
  };
}

// ---------------------------------------------------------------------------------------------
// Change request status in plain words
// ---------------------------------------------------------------------------------------------

export const CR_STATUS_TEXT: Record<string, { label: string; tone: Tone }> = {
  DRAFT: { label: "Draft", tone: "neutral" },
  PENDING_APPROVAL: { label: "Waiting for approval", tone: "warn" },
  APPROVED: { label: "Approved — ready to deploy", tone: "info" },
  REJECTED: { label: "Rejected", tone: "bad" },
  DEPLOYING: { label: "Deploying", tone: "busy" },
  COMPLETED: { label: "Completed", tone: "good" },
  PARTIAL: { label: "Partly completed", tone: "warn" },
  FAILED: { label: "Failed", tone: "bad" },
  CANCELLED: { label: "Cancelled", tone: "neutral" },
};

// ---------------------------------------------------------------------------------------------
// Maintenance windows
// ---------------------------------------------------------------------------------------------

/** Next start of a maintenance window after `now` (invalid cron → null). */
export function nextWindowStart(w: { cron: string; timezone: string }, now: Date): Date | null {
  try {
    return CronExpressionParser.parse(w.cron, { currentDate: now, tz: w.timezone }).next().toDate();
  } catch {
    return null;
  }
}
