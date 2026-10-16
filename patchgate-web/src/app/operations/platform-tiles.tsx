import Link from "next/link";
import { Activity, Award, DownloadCloud, HardDrive, ScrollText, Send } from "lucide-react";
import { Badge, Card, Stat, fmtDate, rowCls, tableCls, theadCls } from "@/components/ui";
import { certRag, fetchRag, repoQuotaRag, siemLagRag, workerStepRag, worst, type Rag } from "@/lib/metrics/thresholds";
import type { OpsSnapshot } from "@/lib/metrics/types";
import { RAG_LABEL, RAG_TONE, STAT_TONE, fmtAge, fmtBytes, fmtMs, secondsSince } from "./format";

function RagBadge({ rag, label }: { rag: Rag; label?: string }) {
  return <Badge tone={RAG_TONE[rag]}>{label ?? RAG_LABEL[rag]}</Badge>;
}

const linkCls = "text-xs font-medium text-primary hover:underline";

export function PlatformStats({ s }: { s: OpsSnapshot }) {
  const p = s.platform;
  const now = s.generatedAt;
  const brokenChains = p.auditChains.filter((c) => !c.valid).length;
  const auditRag: Rag = p.auditChains.length === 0 ? "none" : brokenChains > 0 ? "red" : "green";
  const workerRag = p.workerSteps.length === 0 ? "red" : worst(...p.workerSteps.map((w) => workerStepRag(w, now)));
  const tick = p.workerSteps.find((w) => w.step === "tick");
  const siemRag = siemLagRag(p.siemChains, p.siemConfigured);
  const maxLag = p.siemChains.reduce((m, c) => Math.max(m, c.lagSec), 0);
  const quota = p.repoQuota;
  const quotaPct = quota?.usedBytes !== null && quota?.usedBytes !== undefined && quota.quotaBytes > 0 ? Math.round((quota.usedBytes / quota.quotaBytes) * 100) : null;
  const cert = p.cert;
  const held = Object.values(p.heldPackages).reduce((n, v) => n + v, 0);
  return (
    <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-6">
      <Stat
        label="Worker"
        value={tick ? fmtAge(secondsSince(tick.lastSuccessAt, now)) : "never"}
        tone={STAT_TONE[workerRag]}
        icon={<Activity size={16} />}
        hint={tick ? `since last good tick · took ${fmtMs(tick.lastDurationMs)}` : "no tick recorded yet"}
      />
      <Stat
        label="Audit chains"
        value={brokenChains > 0 ? `${brokenChains} broken` : `${p.auditChains.length} intact`}
        tone={STAT_TONE[auditRag]}
        icon={<ScrollText size={16} />}
        hint={brokenChains > 0 ? "P1 security incident — RUNBOOK §9.5" : "incremental verification"}
      />
      <Stat
        label="SIEM export"
        value={p.siemConfigured ? fmtAge(maxLag) : "off"}
        tone={STAT_TONE[siemRag]}
        icon={<Send size={16} />}
        hint={p.siemConfigured ? "worst chain lag" : "SIEM_SYSLOG_URL not configured"}
      />
      <Stat
        label="Repository"
        value={quotaPct === null ? (quota ? (quota.ok ? "ok" : "over") : "—") : `${quotaPct} %`}
        tone={STAT_TONE[repoQuotaRag(quota)]}
        icon={<HardDrive size={16} />}
        hint={quota ? `${fmtBytes(quota.usedBytes)} of ${fmtBytes(quota.quotaBytes)}` : "quota never measured"}
      />
      <Stat
        label="TLS certificate"
        value={cert?.daysLeft !== null && cert?.daysLeft !== undefined ? `${cert.daysLeft} d` : "—"}
        tone={STAT_TONE[certRag(cert)]}
        icon={<Award size={16} />}
        hint={cert ? (cert.error ? `probe failed (${cert.error})` : `${cert.host} · ${fmtDate(cert.expiresAt)}`) : "PUBLIC_BASE_URL not https"}
      />
      <Stat
        label="Held packages"
        value={held}
        tone={held > 0 ? "warn" : "neutral"}
        icon={<DownloadCloud size={16} />}
        hint="waiting for a trust decision"
      />
    </div>
  );
}

export function WorkerSteps({ s }: { s: OpsSnapshot }) {
  const now = s.generatedAt;
  return (
    <Card title="Worker steps" description="Per-step outcome of the 1-minute tick (all web instances)." padded={false}>
      {s.platform.workerSteps.length === 0 ? (
        <p className="p-5 text-sm text-muted">No tick recorded yet — check the scheduler container.</p>
      ) : (
        <div className="max-h-[28rem] overflow-y-auto">
          <table className={tableCls}>
            <thead className={theadCls}>
              <tr>
                <th>Step</th>
                <th>Last run</th>
                <th>Duration</th>
                <th>Last success</th>
                <th>Errors</th>
              </tr>
            </thead>
            <tbody>
              {s.platform.workerSteps.map((w) => (
                <tr key={w.step} className={rowCls}>
                  <td>
                    <div className="flex items-center gap-2">
                      <RagBadge rag={workerStepRag(w, now)} label={w.lastOk ? "ok" : "failed"} />
                      <span className="font-mono text-xs">{w.step}</span>
                    </div>
                    {!w.lastOk && <div className="mt-1 max-w-xs truncate text-xs text-danger" title={w.lastStatus}>{w.lastStatus}</div>}
                  </td>
                  <td className="whitespace-nowrap text-xs text-muted">{fmtAge(secondsSince(w.lastRunAt, now))} ago</td>
                  <td className="whitespace-nowrap text-xs tabular-nums">{fmtMs(w.lastDurationMs)}</td>
                  <td className="whitespace-nowrap text-xs text-muted">{w.lastSuccessAt ? `${fmtAge(secondsSince(w.lastSuccessAt, now))} ago` : "never"}</td>
                  <td className="text-xs tabular-nums">
                    {w.failures.toLocaleString("en")} / {w.runs.toLocaleString("en")}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

export function FetchAndAudit({ s }: { s: OpsSnapshot }) {
  const now = s.generatedAt;
  const p = s.platform;
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Card title="Fetch runs" description="Internet downloads by source (24 h)." actions={<Link href="/apps" className={linkCls}>Apps & mirror →</Link>} padded={false}>
        {p.fetch.length === 0 ? (
          <p className="p-5 text-sm text-muted">No fetch run recorded yet.</p>
        ) : (
          <table className={tableCls}>
            <thead className={theadCls}>
              <tr>
                <th>Source</th>
                <th>Runs</th>
                <th>Failed</th>
                <th>Last success</th>
              </tr>
            </thead>
            <tbody>
              {p.fetch.map((f) => (
                <tr key={f.source} className={rowCls}>
                  <td>
                    <div className="flex items-center gap-2">
                      <RagBadge rag={fetchRag(f, now)} label={f.failed24h > 0 ? "failures" : "ok"} />
                      <span className="font-mono text-xs">{f.source}</span>
                    </div>
                  </td>
                  <td className="tabular-nums">{f.runs24h}</td>
                  <td className={`tabular-nums ${f.failed24h > 0 ? "text-danger" : ""}`}>{f.failed24h}</td>
                  <td className="whitespace-nowrap text-xs text-muted">{f.lastSuccessAt ? `${fmtAge(secondsSince(f.lastSuccessAt, now))} ago` : "never"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
      <Card title="Audit chains & SIEM export" description="Verification verdict and export lag per chain." actions={<Link href="/audit" className={linkCls}>Audit →</Link>} padded={false}>
        <div className="max-h-[22rem] overflow-y-auto">
          <table className={tableCls}>
            <thead className={theadCls}>
              <tr>
                <th>Chain</th>
                <th>Integrity</th>
                <th>Verified</th>
                <th>Export lag</th>
              </tr>
            </thead>
            <tbody>
              {p.siemChains.map((c) => {
                const v = p.auditChains.find((a) => a.chain === c.chain);
                return (
                  <tr key={c.chain} className={rowCls}>
                    <td className="font-mono text-xs">{c.label}</td>
                    <td>{v ? <RagBadge rag={v.valid ? "green" : "red"} label={v.valid ? "intact" : "BROKEN"} /> : <RagBadge rag="none" label="not verified" />}</td>
                    <td className="whitespace-nowrap text-xs text-muted">{v ? `${fmtAge(secondsSince(v.verifiedAt, now))} ago` : "—"}</td>
                    <td className="whitespace-nowrap text-xs">
                      {!p.siemConfigured ? <span className="text-muted">SIEM off</span> : c.pending ? <RagBadge rag={siemLagRag([c], true)} label={fmtAge(c.lagSec)} /> : <span className="text-muted">up to date</span>}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
