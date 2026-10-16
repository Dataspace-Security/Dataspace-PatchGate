import { EVENT_INFO, type NotificationEvent, type Severity } from "./events";

/**
 * Message rendering (pure). One structure per event → plain text, HTML (every value escaped) and a short
 * subject. Messages carry identifiers and facts only: never secrets, tokens, temporary passwords or package
 * bytes. Links point to PUBLIC_BASE_URL (omitted when it is not configured).
 */

export interface MessageFacts {
  bankName?: string | null;
  /** Change request */
  crId?: string;
  crTitle?: string;
  ticketRef?: string | null;
  emergency?: boolean;
  maker?: string | null;
  actor?: string | null;
  reason?: string | null;
  targets?: number | null;
  status?: string;
  succeeded?: number;
  failed?: number;
  total?: number;
  failureRatePct?: number;
  stopped?: number;
  timedOut?: number;
  deadline?: Date | null;
  /** Connector */
  connectorId?: string;
  connectorName?: string;
  lastSeenAt?: Date | null;
  offlineMinutes?: number;
  /** Windows Update lock */
  endpointCount?: number;
  hostnames?: string;
  issues?: string | null;
  /** Package trust */
  appName?: string;
  wingetId?: string;
  version?: string;
  holdReason?: string | null;
  signerOrg?: string | null;
  sha256?: string | null;
  /** Audit / SIEM */
  chain?: string;
  problem?: string | null;
  pending?: number;
  minutesSinceExport?: number | null;
  /** Account */
  userName?: string;
  until?: Date | null;
}

export interface RenderedMessage {
  subject: string;
  text: string;
  html: string;
  link: string | null;
}

interface Layout {
  subject: string;
  intro: string;
  fields: [string, string | number | null | undefined][];
  path: string | null;
}

const MAX_VALUE = 500;
const MAX_SUBJECT = 200;

/** One line, bounded, no control characters (header injection, log forging). */
export function oneLine(v: string, max = MAX_VALUE): string {
  const s = v.replace(/[\u0000-\u001f\u007f]+/g, " ").replace(/\s+/g, " ").trim();
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

export function escapeHtml(v: string): string {
  return v.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] ?? c);
}

function iso(d: Date | null | undefined): string | null {
  return d ? d.toISOString().replace("T", " ").slice(0, 16) + " UTC" : null;
}

function bank(f: MessageFacts): string {
  return f.bankName ? ` — ${f.bankName}` : "";
}

function crFields(f: MessageFacts): Layout["fields"] {
  return [
    ["Bank", f.bankName],
    ["Change request", f.crTitle],
    ["Ticket", f.ticketRef],
    ["Emergency", f.emergency ? "yes" : null],
    ["Maker", f.maker],
  ];
}

function layout(event: NotificationEvent, f: MessageFacts): Layout {
  const crPath = f.crId ? `/change-requests/${encodeURIComponent(f.crId)}` : "/change-requests";
  switch (event) {
    case "CR_SUBMITTED":
      return {
        subject: `${f.emergency ? "EMERGENCY change" : "Change request"} awaiting approval: ${f.crTitle ?? ""}${bank(f)}`,
        intro: "A change request was submitted and needs a checker decision.",
        fields: [...crFields(f), ["Target endpoints", f.targets]],
        path: crPath,
      };
    case "CR_APPROVED":
      return {
        subject: `Change request approved: ${f.crTitle ?? ""}${bank(f)}`,
        intro: "Your change request was approved and can be deployed.",
        fields: [...crFields(f), ["Approved by", f.actor], ["Target endpoints", f.targets]],
        path: crPath,
      };
    case "CR_REJECTED":
      return {
        subject: `Change request rejected: ${f.crTitle ?? ""}${bank(f)}`,
        intro: "Your change request was rejected.",
        fields: [...crFields(f), ["Rejected by", f.actor], ["Reason", f.reason]],
        path: crPath,
      };
    case "RING_STOPPED":
      return {
        subject: `Deployment stopped: ${f.crTitle ?? ""}${bank(f)}`,
        intro: "The rollout was stopped because too many installs failed. Deployments not yet started were cancelled.",
        fields: [...crFields(f), ["Succeeded", f.succeeded], ["Failed", f.failed], ["Failure rate", f.failureRatePct !== undefined ? `${f.failureRatePct} %` : null], ["Deployments stopped", f.stopped]],
        path: crPath,
      };
    case "CR_FAILED":
      return {
        subject: `Change request finished ${f.status === "FAILED" ? "FAILED" : "with failures"}: ${f.crTitle ?? ""}${bank(f)}`,
        intro: "The change request finished, but not every endpoint was patched.",
        fields: [...crFields(f), ["Result", f.status], ["Succeeded", f.succeeded !== undefined && f.total !== undefined ? `${f.succeeded} of ${f.total}` : null]],
        path: crPath,
      };
    case "CR_DEADLINE":
      return {
        subject: `Deployment deadline reached: ${f.crTitle ?? ""}${bank(f)}`,
        intro: "The change request's deployment deadline passed; installs that had not started were timed out.",
        fields: [...crFields(f), ["Deadline", iso(f.deadline)], ["Timed out", f.timedOut]],
        path: crPath,
      };
    case "CONNECTOR_OFFLINE":
      return {
        subject: `Site connector offline: ${f.connectorName ?? ""}${bank(f)}`,
        intro: "No heartbeat from this site connector for more than 10 minutes. Jobs wait and are not lost.",
        fields: [["Bank", f.bankName], ["Connector", f.connectorName], ["Last heartbeat", iso(f.lastSeenAt) ?? "never"]],
        path: "/connectors",
      };
    case "CONNECTOR_ONLINE":
      return {
        subject: `Site connector back online: ${f.connectorName ?? ""}${bank(f)}`,
        intro: "The site connector is sending heartbeats again.",
        fields: [["Bank", f.bankName], ["Connector", f.connectorName], ["Offline for", f.offlineMinutes !== undefined ? `${f.offlineMinutes} min` : null]],
        path: "/connectors",
      };
    case "WU_LOCK_BROKEN":
      return {
        subject: `Windows Update NOT locked on ${f.endpointCount ?? "?"} PC${f.endpointCount === 1 ? "" : "s"}${bank(f)}`,
        intro:
          "These PCs could take Windows updates directly from Microsoft, outside PatchGate. Re-run Install-PatchGateAgent.ps1 on them (or fix the GPO); see RUNBOOK \"PatchGate locks Windows Update\".",
        fields: [["Bank", f.bankName], ["Connector", f.connectorName], ["PCs", f.hostnames], ["Problems", f.issues]],
        path: "/endpoints",
      };
    case "PACKAGE_HELD":
      return {
        subject: `Package held for trust decision: ${f.appName ?? f.wingetId ?? ""} ${f.version ?? ""}`,
        intro: "A downloaded package passed hash/signature checks but needs a platform administrator's trust decision.",
        fields: [["App", f.appName], ["Package", f.wingetId], ["Version", f.version], ["Reason", f.holdReason], ["Signer", f.signerOrg], ["SHA-256", f.sha256]],
        path: "/apps",
      };
    case "AUDIT_CHAIN_BROKEN":
      return {
        subject: `CRITICAL: audit chain verification failed (${f.chain ?? "?"})`,
        intro: "Incremental verification found the audit chain broken — treat as a possible tampering incident (RUNBOOK §9.5).",
        fields: [["Chain", f.chain], ["Bank", f.bankName], ["Problem", f.problem]],
        path: "/audit",
      };
    case "SIEM_EXPORT_STALE":
      return {
        subject: `CRITICAL: SIEM audit export stale (${f.chain ?? "?"})`,
        intro: "Audit events are waiting and the last SIEM export is older than 15 minutes.",
        fields: [["Chain", f.chain], ["Bank", f.bankName], ["Events not exported", f.pending], ["Last export", f.minutesSinceExport === null || f.minutesSinceExport === undefined ? "never" : `${f.minutesSinceExport} min ago`]],
        path: "/audit",
      };
    case "TACTICAL_OUT_OF_BAND":
      return {
        subject: `CRITICAL: ${f.total ?? 1} action(s) in Tactical outside PatchGate: ${f.connectorName ?? ""}${bank(f)}`,
        intro:
          "Someone used the site's Tactical RMM directly (dashboard login, script, command, approval or setting change) instead of PatchGate. Check who did it and why; acknowledge it on the Connectors page (RUNBOOK \"Tactical is sealed\").",
        fields: [["Bank", f.bankName], ["Site connector", f.connectorName], ["Actions", f.total], ["Latest", f.problem]],
        path: "/connectors",
      };
    case "APPROVAL_SETTING_CHANGED":
      return {
        subject: `Approval switched ${f.status === "ON" ? "ON" : "OFF"}${bank(f)}`,
        intro:
          f.status === "ON"
            ? "Approval is required again: every change request needs an admin of the bank other than the maker before it can be deployed."
            : "Approval is OFF: change requests of this bank are approved on submit and can be deployed WITHOUT a second person. If this was not intended, switch it back on (Settings → Approval policy).",
        fields: [["Bank", f.bankName], ["Approval required", f.status === "ON" ? "yes" : "no"], ["Changed by", f.actor]],
        path: "/settings/approvals",
      };
    case "ACCOUNT_LOCKED":
      return {
        subject: "Your PatchGate account was locked",
        intro: "Too many failed sign-in attempts locked your account. If this was not you, tell your administrator.",
        fields: [["Account", f.userName], ["Locked until", iso(f.until)]],
        path: "/login",
      };
    case "PASSWORD_RESET":
      return {
        subject: "Your PatchGate password was reset",
        intro: "An administrator reset your password. Your administrator gives you the temporary password; you must change it at the next sign-in. If you did not expect this, contact your administrator.",
        fields: [["Account", f.userName], ["Reset by", f.actor]],
        path: "/login",
      };
  }
}

/** Absolute link on the public base URL (http(s) only), or null. */
export function publicLink(baseUrl: string | null | undefined, path: string | null): string | null {
  if (!baseUrl || !path) return null;
  try {
    const base = new URL(baseUrl);
    if (base.protocol !== "https:" && base.protocol !== "http:") return null;
    return new URL(path, base).toString();
  } catch {
    return null;
  }
}

const SEVERITY_COLOR: Record<Severity, string> = { info: "#2563eb", warning: "#b45309", critical: "#b91c1c" };

export function renderMessage(event: NotificationEvent, facts: MessageFacts, baseUrl?: string | null): RenderedMessage {
  const l = layout(event, facts);
  const severity = EVENT_INFO[event].severity;
  const fields = l.fields
    .filter((x): x is [string, string | number] => x[1] !== null && x[1] !== undefined && x[1] !== "")
    .map(([k, v]) => [k, oneLine(String(v))] as const);
  const link = publicLink(baseUrl, l.path);
  const subject = oneLine(`[PatchGate] ${l.subject}`, MAX_SUBJECT);

  const text = [l.intro, "", ...fields.map(([k, v]) => `${k}: ${v}`), ...(link ? ["", `Open: ${link}`] : []), "", "— PatchGate (automated message, do not reply)"].join("\n");

  const rows = fields
    .map(([k, v]) => `<tr><td style="padding:4px 12px 4px 0;color:#555;white-space:nowrap">${escapeHtml(k)}</td><td style="padding:4px 0">${escapeHtml(v)}</td></tr>`)
    .join("");
  const html = [
    `<!doctype html><html><body style="font-family:Segoe UI,Arial,sans-serif;font-size:14px;color:#111">`,
    `<p style="margin:0 0 4px;font-size:12px;font-weight:600;text-transform:uppercase;color:${SEVERITY_COLOR[severity]}">${escapeHtml(severity)}</p>`,
    `<p style="margin:0 0 12px">${escapeHtml(l.intro)}</p>`,
    `<table style="border-collapse:collapse">${rows}</table>`,
    link ? `<p style="margin:16px 0 0"><a href="${escapeHtml(link)}">Open in PatchGate</a></p>` : "",
    `<p style="margin:16px 0 0;font-size:12px;color:#777">PatchGate — automated message, do not reply.</p>`,
    `</body></html>`,
  ].join("");
  return { subject, text, html, link };
}

/** Teams / Slack compatible incoming-webhook body ({ text } is understood by both). */
export function webhookPayload(n: { event: string; severity: string; subject: string; bodyText: string; link: string | null; createdAt: Date }): Record<string, unknown> {
  const text = `*${n.subject}*\n${n.bodyText.replace(/\n— PatchGate \(automated message, do not reply\)$/, "")}`;
  return {
    text,
    summary: n.subject,
    patchgate: { event: n.event, severity: n.severity, link: n.link, createdAt: n.createdAt.toISOString() },
  };
}
