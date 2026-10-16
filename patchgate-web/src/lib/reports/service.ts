import "server-only";
import { appendAudit } from "@/lib/audit/service";
import type { SessionUser } from "@/lib/auth/session";
import { DomainError } from "@/lib/errors";
import { resolveActiveTenant } from "@/lib/tenancy/context";
import { withTenant } from "@/lib/tenancy/db";
import { buildBankReport, buildPlatformSummary } from "./build";
import { canonicalJson, contentHash, csvLine } from "./csv";
import { nonCompliantPage } from "./fleet";
import { renderBankReportHtml, renderPlatformSummaryHtml, tableCsv } from "./html";
import { PeriodError, parsePeriod, type Period, type PeriodParams } from "./period";
import { sectionTable, summaryTable, type BankSection } from "./sections";
import type { BankReport, PlatformSummary } from "./types";

/**
 * Who sees which report, and the audited exports.
 *  - Bank users (any role): their own bank only — a requested bank / "all" is ignored.
 *  - Platform staff: the bank selected with the switcher, or the all-banks summary (`scope=all`, or no bank).
 * Printable HTML and CSV exports are "generated reports": each is audited (bank chain for a bank report,
 * platform chain for the summary) with the period, format and the SHA-256 of the content.
 */

export type ReportScope = { kind: "bank"; tenantId: string; bankName: string } | { kind: "all" };

export async function resolveReportScope(user: SessionUser, requested: string | null | undefined): Promise<ReportScope> {
  const tenant = await resolveActiveTenant(user);
  if (user.tenantId !== null) {
    if (!tenant) throw new DomainError("Bank not found", 404);
    return { kind: "bank", tenantId: tenant.id, bankName: tenant.name };
  }
  if (requested === "all" || !tenant) return { kind: "all" };
  return { kind: "bank", tenantId: tenant.id, bankName: tenant.name };
}

export function periodFromParams(p: PeriodParams, now = new Date()): Period {
  try {
    return parsePeriod(p, now);
  } catch (err: unknown) {
    if (err instanceof PeriodError) throw new DomainError(err.message, 400);
    throw err;
  }
}

export function periodParamsOf(sp: URLSearchParams | Record<string, string | string[] | undefined>): PeriodParams {
  const get = (k: string): string | null => {
    if (sp instanceof URLSearchParams) return sp.get(k);
    const v = sp[k];
    return (Array.isArray(v) ? v[0] : v) ?? null;
  };
  return { period: get("period"), month: get("month"), quarter: get("quarter"), from: get("from"), to: get("to") };
}

export async function loadReport(user: SessionUser, scope: ReportScope, period: Period, now = new Date()): Promise<BankReport | PlatformSummary> {
  return scope.kind === "bank" ? buildBankReport(scope.tenantId, period, user.upn, now) : buildPlatformSummary(period, user.upn, now);
}

async function auditGenerated(user: SessionUser, scope: ReportScope, period: Period, format: string, sha256: string | null, section?: string): Promise<void> {
  await appendAudit({
    tenantId: scope.kind === "bank" ? scope.tenantId : null,
    actor: user.upn,
    action: "report.generate",
    entity: "ComplianceReport",
    entityId: scope.kind === "bank" ? scope.tenantId : "all-banks",
    payload: { format, section: section ?? null, period: period.label, from: period.from.toISOString(), to: period.to.toISOString(), sha256, actorBank: user.tenantId ?? "platform" },
  });
}

/** Printable HTML document + its content hash (audited). */
export async function generatePrintable(user: SessionUser, scope: ReportScope, period: Period): Promise<{ html: string; sha256: string }> {
  const data = await loadReport(user, scope, period);
  const sha256 = contentHash(data);
  const html = "fleet" in data ? renderBankReportHtml(data, sha256) : renderPlatformSummaryHtml(data, sha256);
  await auditGenerated(user, scope, period, "html", sha256);
  return { html, sha256 };
}

const ENDPOINT_PAGE = 2_000;
const enc = new TextEncoder();

/** Streamed CSV of non-compliant endpoints (keyset pages, one short RLS transaction per page). */
function nonCompliantStream(tenantId: string): ReadableStream<Uint8Array> {
  let after = "";
  let headerSent = false;
  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      try {
        if (!headerSent) {
          headerSent = true;
          controller.enqueue(enc.encode(csvLine(["endpoint_id", "hostname", "site", "ring", "last_scan_at", "missing_critical_important", "missing_critical", "oldest_missing_released_at"])));
          return;
        }
        const page = await withTenant(tenantId, (tx) => nonCompliantPage(tx, tenantId, after, ENDPOINT_PAGE));
        if (page.length === 0) {
          controller.close();
          return;
        }
        after = page[page.length - 1].endpointId;
        controller.enqueue(enc.encode(page.map((r) => csvLine([r.endpointId, r.hostname, r.site, r.ring, r.lastScanAt, r.gaps, r.critical, r.oldestReleasedAt])).join("")));
        if (page.length < ENDPOINT_PAGE) controller.close();
      } catch (err: unknown) {
        controller.error(err);
      }
    },
  });
}

const AUDIT_PAGE = 2_000;

/**
 * Streamed CSV of one bank's audit chain in a period (keyset pages by seq, one short RLS transaction each).
 * Carries payload, prev_hash and hash so an auditor can re-check the chain offline against the SIEM anchors.
 * Spreadsheet safety (csvCell): a text cell starting with = + - @ is prefixed with ' — strip that prefix before
 * re-hashing actor / entity / entity_id (payload_json always starts with "{").
 */
function auditLogStream(tenantId: string, period: Period): ReadableStream<Uint8Array> {
  let after = BigInt(0);
  let headerSent = false;
  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      try {
        if (!headerSent) {
          headerSent = true;
          controller.enqueue(enc.encode(csvLine(["seq", "time_utc", "actor", "action", "entity", "entity_id", "payload_json", "prev_hash", "hash"])));
          return;
        }
        const page = await withTenant(tenantId, (tx) =>
          tx.auditEvent.findMany({
            where: { tenantId, ts: { gte: period.from, lt: period.to }, seq: { gt: after } },
            orderBy: { seq: "asc" },
            take: AUDIT_PAGE,
          }),
        );
        if (page.length === 0) {
          controller.close();
          return;
        }
        after = page[page.length - 1].seq;
        controller.enqueue(
          enc.encode(page.map((e) => csvLine([e.seq.toString(), e.ts.toISOString(), e.actor, e.action, e.entity, e.entityId, canonicalJson(e.payload), e.prevHash, e.hash])).join("")),
        );
        if (page.length < AUDIT_PAGE) controller.close();
      } catch (err: unknown) {
        controller.error(err);
      }
    },
  });
}

/** The selected bank's audit events of a period as CSV (audited like every report export). */
export async function exportAuditLogCsv(user: SessionUser, scope: ReportScope, period: Period): Promise<CsvExport> {
  if (scope.kind !== "bank") throw new DomainError("Select a bank first: the audit log is exported per bank chain", 400);
  await auditGenerated(user, scope, period, "csv", null, "audit-log"); // streamed: no content hash
  return { filename: `patchgate-${slug(scope.bankName)}-audit-log-${period.from.toISOString().slice(0, 10)}.csv`, body: auditLogStream(scope.tenantId, period) };
}

export interface CsvExport {
  filename: string;
  body: ReadableStream<Uint8Array> | string;
}

function slug(v: string): string {
  return v.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 40) || "report";
}

/** CSV of one section (audited). The bank summary scope exports the all-banks table. */
export async function exportCsv(user: SessionUser, scope: ReportScope, period: Period, section: BankSection): Promise<CsvExport> {
  const stamp = period.from.toISOString().slice(0, 10);
  if (scope.kind === "all") {
    const s = await buildPlatformSummary(period, user.upn);
    const t = summaryTable(s);
    await auditGenerated(user, scope, period, "csv", contentHash(t), "all-banks");
    return { filename: `patchgate-all-banks-${stamp}.csv`, body: tableCsv(t) };
  }
  const filename = `patchgate-${slug(scope.bankName)}-${section}-${stamp}.csv`;
  if (section === "noncompliant") {
    await auditGenerated(user, scope, period, "csv", null, section); // streamed: no content hash
    return { filename, body: nonCompliantStream(scope.tenantId) };
  }
  const r = await buildBankReport(scope.tenantId, period, user.upn);
  const t = sectionTable(r, section);
  await auditGenerated(user, scope, period, "csv", contentHash(t), section);
  return { filename, body: tableCsv(t) };
}
