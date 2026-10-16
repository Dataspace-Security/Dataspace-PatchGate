import Link from "next/link";
import { Suspense } from "react";
import { AlertTriangle, Download, Monitor, Printer, ShieldCheck } from "lucide-react";
import { getPageUser } from "@/lib/auth/page-user";
import { DomainError } from "@/lib/errors";
import type { Cell } from "@/lib/reports/csv";
import { BANK_SECTIONS, SECTION_LABEL, sectionTable, summaryTable, type BankSection, type SectionTable } from "@/lib/reports/sections";
import { loadReport, periodFromParams, periodParamsOf, resolveReportScope } from "@/lib/reports/service";
import type { BankReport, PlatformSummary } from "@/lib/reports/types";
import { Alert, BUTTON, Card, Loading, PageHeader, Stat, buttonBase, fmtDate, inputCls, labelCls, rowCls, tableCls, theadCls } from "@/components/ui";

type SearchParams = Promise<Record<string, string | string[] | undefined>>;

function first(v: string | string[] | undefined): string | undefined {
  return Array.isArray(v) ? v[0] : v;
}

function fmt(v: Cell): string {
  if (v instanceof Date) return fmtDate(v);
  if (typeof v === "boolean") return v ? "yes" : "no";
  if (v === null || v === undefined || v === "") return "—";
  return Array.isArray(v) ? v.join(", ") : String(v);
}

function DataTable({ t, empty = "Nothing in this period." }: { t: SectionTable; empty?: string }) {
  if (t.rows.length === 0) return <p className="px-5 py-4 text-sm text-muted">{empty}</p>;
  return (
    <div className="overflow-x-auto">
      <table className={tableCls}>
        <thead className={theadCls}>
          <tr>
            {t.header.map((h) => (
              <th key={h}>{h.replaceAll("_", " ")}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {t.rows.map((r, i) => (
            <tr key={i} className={rowCls}>
              {r.map((c, j) => (
                <td key={j} className={typeof c === "number" ? "text-right tabular-nums" : "max-w-md break-words"}>
                  {fmt(c)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function PeriodForm({ sp, scopeAll }: { sp: Record<string, string | string[] | undefined>; scopeAll: boolean }) {
  const kind = first(sp.period) ?? "month";
  return (
    <form method="get" className="flex flex-wrap items-end gap-3 rounded-xl border border-border bg-surface p-4 shadow-card">
      {scopeAll && <input type="hidden" name="scope" value="all" />}
      <label className={labelCls}>
        Period
        <select name="period" defaultValue={kind} className={inputCls}>
          <option value="month">Month</option>
          <option value="quarter">Quarter</option>
          <option value="custom">Custom</option>
        </select>
      </label>
      <label className={labelCls}>
        Month
        <input type="month" name="month" defaultValue={first(sp.month)} className={inputCls} />
      </label>
      <label className={labelCls}>
        Quarter
        <input type="text" name="quarter" placeholder="2026-Q4" pattern="\d{4}-[Qq][1-4]" defaultValue={first(sp.quarter)} className={inputCls} />
      </label>
      <label className={labelCls}>
        From
        <input type="date" name="from" defaultValue={first(sp.from)} className={inputCls} />
      </label>
      <label className={labelCls}>
        To
        <input type="date" name="to" defaultValue={first(sp.to)} className={inputCls} />
      </label>
      <button type="submit" className={`${buttonBase} ${BUTTON.primary}`}>
        Show
      </button>
    </form>
  );
}

function csvHref(query: string, section: BankSection | "summary", all: boolean): string {
  return `/api/reports/csv?${query}&section=${section}${all ? "&scope=all" : ""}`;
}

function BankView({ r, query }: { r: BankReport; query: string }) {
  const e = r.evidence;
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Stat label="Fleet" value={r.fleet.endpoints} icon={<Monitor size={18} />} hint={`${r.fleet.scanned} scanned`} />
        <Stat
          label="Compliant"
          value={r.fleet.compliancePct === null ? "—" : `${r.fleet.compliancePct} %`}
          tone={r.fleet.compliancePct === null ? "neutral" : r.fleet.compliancePct >= 95 ? "good" : r.fleet.compliancePct >= 80 ? "warn" : "bad"}
          icon={<ShieldCheck size={18} />}
          hint="no missing critical / important patch"
        />
        <Stat label="Critical gaps" value={r.fleet.criticalMissing} tone={r.fleet.criticalMissing > 0 ? "bad" : "good"} icon={<AlertTriangle size={18} />} hint="missing installs" />
        <Stat label="Important gaps" value={r.fleet.importantMissing} tone={r.fleet.importantMissing > 0 ? "warn" : "good"} hint="missing installs" />
      </div>
      <Alert tone={e.verified === false ? "bad" : e.coversPeriod ? "good" : "info"}>
        Audit evidence: chain head at period end {e.headSeq ? `seq ${e.headSeq}` : "— (no events)"}
        {e.headHash ? `, hash ${e.headHash.slice(0, 16)}…` : ""}; {e.eventsInPeriod} events in the period.{" "}
        {e.verified === null ? "Not verified yet." : e.verified ? `Verified intact through seq ${e.verifiedThroughSeq} (${fmtDate(e.verifiedAt)}).` : `VERIFICATION FAILED: ${e.problem ?? "chain broken"}.`}
      </Alert>
      {BANK_SECTIONS.filter((s): s is Exclude<BankSection, "noncompliant" | "summary"> => s !== "noncompliant" && s !== "summary").map((s) => (
        <Card
          key={s}
          title={SECTION_LABEL[s]}
          padded={false}
          actions={
            <a href={csvHref(query, s, false)} className="inline-flex items-center gap-1 text-xs font-medium text-primary hover:underline">
              <Download size={13} /> CSV
            </a>
          }
        >
          <DataTable t={sectionTable(r, s)} />
        </Card>
      ))}
      <p className="text-xs text-muted">
        Compliance is a snapshot at generation time; activity sections cover the selected period. Per-endpoint detail:{" "}
        <a className="text-primary hover:underline" href={csvHref(query, "noncompliant", false)}>
          non-compliant endpoints (CSV)
        </a>
        .
      </p>
    </div>
  );
}

function SummaryView({ s }: { s: PlatformSummary }) {
  return (
    <Card title="All banks" description="Select a bank with the bank switcher for its full report." padded={false}>
      <DataTable t={summaryTable(s)} empty="No active banks." />
    </Card>
  );
}

async function ReportsContent({ searchParams }: { searchParams: SearchParams }) {
  const sp = await searchParams;
  const user = await getPageUser();
  let period;
  try {
    period = periodFromParams(periodParamsOf(sp));
  } catch (err: unknown) {
    if (err instanceof DomainError) return <Alert tone="bad">{err.message}</Alert>;
    throw err;
  }
  const scope = await resolveReportScope(user, first(sp.scope));
  const data = await loadReport(user, scope, period);
  const all = scope.kind === "all";
  const query = period.query;
  const platform = user.tenantId === null;

  return (
    <div className="space-y-6">
      <PeriodForm sp={sp} scopeAll={all} />
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="text-sm">
          <span className="font-semibold text-fg">{scope.kind === "bank" ? scope.bankName : "All banks"}</span>
          <span className="text-muted"> · {period.label} · generated {fmtDate(data.meta.generatedAt)}</span>
          {platform && (
            <Link href={`/reports?${query}${all ? "" : "&scope=all"}`} className="ml-3 font-medium text-primary hover:underline">
              {all ? "Selected bank’s report" : "All-banks summary"}
            </Link>
          )}
        </div>
        <div className="flex gap-2">
          <a href={csvHref(query, "summary", all)} className={`${buttonBase} ${BUTTON.default}`}>
            <Download size={15} /> Summary CSV
          </a>
          <a href={`/api/reports/print?${query}${all ? "&scope=all" : ""}`} target="_blank" rel="noopener" className={`${buttonBase} ${BUTTON.primary}`}>
            <Printer size={15} /> Printable report
          </a>
        </div>
      </div>
      {"fleet" in data ? <BankView r={data} query={query} /> : <SummaryView s={data} />}
    </div>
  );
}

export default function ReportsPage({ searchParams }: { searchParams: SearchParams }) {
  return (
    <div>
      <PageHeader
        title="Compliance reports"
        description="Patch compliance, change activity, exceptions, connector uptime and audit evidence for a period. Exports (CSV, printable PDF) are recorded in the audit chain with their SHA-256."
      />
      <Suspense fallback={<Loading />}>
        <ReportsContent searchParams={searchParams} />
      </Suspense>
    </div>
  );
}
