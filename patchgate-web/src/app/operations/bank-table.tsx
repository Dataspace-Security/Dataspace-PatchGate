import type { ReactNode } from "react";
import Link from "next/link";
import { Badge, EmptyState, rowCls, tableCls, tableWrapCls, theadCls } from "@/components/ui";
import type { OpsBankRow, OpsFilter } from "@/lib/metrics/operations";
import { THRESHOLDS, type Rag } from "@/lib/metrics/thresholds";
import { RAG_LABEL, fmtAge, fmtBytes, fmtPct } from "./format";
import { OpenBankLink } from "./open-bank-link";

function Dot({ rag, title }: { rag: Rag; title?: string }) {
  const cls = { green: "bg-success", amber: "bg-warning", red: "bg-danger", none: "bg-border-strong" }[rag];
  return <span aria-label={title ?? RAG_LABEL[rag]} title={title ?? RAG_LABEL[rag]} className={`inline-block h-2.5 w-2.5 shrink-0 rounded-full ${cls}`} />;
}

function Cell({ rag, children }: { rag: Rag; children: ReactNode }) {
  return (
    <div className="flex items-start gap-2">
      <span className="mt-1.5">
        <Dot rag={rag} />
      </span>
      <div className="min-w-0 space-y-0.5">{children}</div>
    </div>
  );
}

const sub = "text-xs text-muted";

function Row({ r }: { r: OpsBankRow }) {
  const b = r.bank;
  const total = b.connectors.length;
  const relay = b.connectors.filter((c) => c.siemConfigured !== null);
  const relayErrors = relay.filter((c) => c.siemConfigured && c.siemOk === false).length;
  const relayOn = relay.filter((c) => c.siemConfigured).length;
  const tacticalBad = b.connectors.filter((c) => c.online && (c.tacticalHealth === "natsdown" || c.tacticalHealth === "unreachable"));
  return (
    <tr className={rowCls}>
      <td>
        <div className="flex items-start gap-2">
          <span className="mt-1.5">
            <Dot rag={r.rag.overall} />
          </span>
          <div className="min-w-0">
            <OpenBankLink tenantId={b.tenantId} href="/" label={b.name} className="text-left font-medium text-fg hover:text-primary hover:underline" />
            <div className={sub}>
              <span className="font-mono">{b.slug}</span> · {b.endpoints.toLocaleString("en")} PCs
              {!b.active && <> · <Badge tone="neutral">suspended</Badge></>}
            </div>
          </div>
        </div>
      </td>
      <td>
        <Cell rag={r.rag.connectors}>
          {total === 0 ? (
            <span className="text-muted">none enrolled</span>
          ) : (
            <OpenBankLink tenantId={b.tenantId} href="/connectors" label={`${r.online}/${total} online`} />
          )}
          {total > 0 && <div className={sub}>stalest seen {fmtAge(r.worstLastSeenAgeSec)} ago</div>}
          {total > 0 && <div className={sub}>v {r.versions.join(", ")} · cache free {fmtBytes(r.minCacheFreeBytes)}</div>}
          {tacticalBad.length > 0 && (
            <div className="text-xs text-danger">
              Tactical {tacticalBad.map((c) => `${c.tacticalHealth === "natsdown" ? "messaging down" : "unreachable"} at ${c.name}${c.tacticalUnhealthySec ? ` (${fmtAge(c.tacticalUnhealthySec)})` : ""}`).join(", ")}
            </div>
          )}
        </Cell>
      </td>
      <td>
        <Cell rag={r.rag.backlog}>
          <span className="tabular-nums">{r.openJobs.toLocaleString("en")} open</span>
          <div className={sub}>oldest due {b.oldestQueuedAgeSec === null ? "—" : fmtAge(b.oldestQueuedAgeSec)}</div>
        </Cell>
      </td>
      <td>
        <Cell rag={r.rag.failures}>
          <span className="tabular-nums">{r.failed24h.toLocaleString("en")} failed</span>
          <div className={sub}>
            {r.failureRate === null ? "no jobs finished" : `${fmtPct(r.failureRate * 100)} of ${(r.failed24h + b.jobsSucceeded24h).toLocaleString("en")}`}
          </div>
        </Cell>
      </td>
      <td>
        <Cell rag={r.rag.approvals}>
          {b.crPendingApproval === 0 ? (
            <span className="text-muted">none waiting</span>
          ) : (
            <OpenBankLink tenantId={b.tenantId} href="/change-requests" label={`${b.crPendingApproval} waiting`} />
          )}
          {b.crPendingApproval > 0 && <div className={sub}>oldest {fmtAge(b.crOldestPendingAgeSec)}</div>}
        </Cell>
      </td>
      <td>
        <Cell rag={r.rag.compliance}>
          {b.compliance === null ? (
            <span className="text-muted">refreshing…</span>
          ) : (
            <OpenBankLink tenantId={b.tenantId} href="/endpoints" label={fmtPct(r.compliancePct)} />
          )}
          {b.compliance && (b.compliance.critical > 0 || b.compliance.important > 0) && (
            <div className={sub}>
              {b.compliance.critical.toLocaleString("en")} critical · {b.compliance.important.toLocaleString("en")} important
            </div>
          )}
        </Cell>
      </td>
      <td>
        <Cell rag={r.rag.siemRelay}>
          {relay.length === 0 ? (
            <span className="text-muted">not reported</span>
          ) : relayErrors > 0 ? (
            <span className="text-danger">{relayErrors} relay error{relayErrors > 1 ? "s" : ""}</span>
          ) : (
            <span>{relayOn}/{relay.length} relaying</span>
          )}
          <div className={sub}>
            <OpenBankLink tenantId={b.tenantId} href="/audit" label="audit & export" className="text-xs text-primary hover:underline" />
          </div>
        </Cell>
      </td>
    </tr>
  );
}

function pageHref(page: number, filter: OpsFilter): string {
  const p = new URLSearchParams();
  if (page > 1) p.set("page", String(page));
  if (filter !== "all") p.set("filter", filter);
  const q = p.toString();
  return q ? `/operations?${q}` : "/operations";
}

export function BankTable(props: { rows: OpsBankRow[]; page: number; pages: number; matching: number; total: number; issues: number; filter: OpsFilter }) {
  const { rows, page, pages, matching, total, issues, filter } = props;
  const tab = "rounded-lg px-3 py-1.5 text-sm font-medium aria-[current=page]:bg-primary aria-[current=page]:text-primary-fg text-muted hover:text-fg";
  return (
    <section className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold text-fg">Banks</h2>
          <p className="text-xs text-muted">
            Worst first. Thresholds: connector offline &gt; {THRESHOLDS.connectorOfflineSec / 60} min, oldest due job &gt; {THRESHOLDS.jobQueuedRedSec / 3600} h,
            job failures &gt; {THRESHOLDS.jobFailureRed * 100} %, approval waiting &gt; {THRESHOLDS.crWaitingRedSec / 3600} h, compliance &lt; {THRESHOLDS.complianceAmber * 100} %.
            Opening a bank switches the bank you act for (audited).
          </p>
        </div>
        <nav aria-label="Filter banks" className="flex gap-1 rounded-xl border border-border bg-surface p-1">
          <Link href={pageHref(1, "all")} aria-current={filter === "all" ? "page" : undefined} className={tab}>
            All ({total})
          </Link>
          <Link href={pageHref(1, "issues")} aria-current={filter === "issues" ? "page" : undefined} className={tab}>
            Needs attention ({issues})
          </Link>
        </nav>
      </div>
      {rows.length === 0 ? (
        <EmptyState title={filter === "issues" ? "Every bank is healthy" : "No banks yet"}>
          {filter === "issues" ? "Nothing is amber or red right now." : "Onboard a bank under Admin → Banks."}
        </EmptyState>
      ) : (
        <div className={tableWrapCls}>
          <table className={tableCls}>
            <thead className={theadCls}>
              <tr>
                <th>Bank</th>
                <th>Connectors</th>
                <th>Job backlog</th>
                <th>Failures 24 h</th>
                <th>Approvals</th>
                <th>Compliance</th>
                <th>SIEM relay</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <Row key={r.bank.tenantId} r={r} />
              ))}
            </tbody>
          </table>
        </div>
      )}
      {pages > 1 && (
        <nav aria-label="Pages" className="flex items-center justify-between text-sm text-muted">
          <span>
            Page {page} of {pages} · {matching} bank{matching === 1 ? "" : "s"}
          </span>
          <span className="flex gap-2">
            {page > 1 && (
              <Link className="text-primary hover:underline" href={pageHref(page - 1, filter)}>
                ← Previous
              </Link>
            )}
            {page < pages && (
              <Link className="text-primary hover:underline" href={pageHref(page + 1, filter)}>
                Next →
              </Link>
            )}
          </span>
        </nav>
      )}
    </section>
  );
}
