import Link from "next/link";
import { Suspense } from "react";
import { AlertTriangle, ArrowRight, Cable, CheckCircle2, Clock, Monitor, Rocket, ShieldAlert, ShieldCheck, Waypoints } from "lucide-react";
import { auditExportStatus } from "@/lib/audit/export";
import { connectorHealth } from "@/lib/connector/admin";
import { directTacticalConfig, legacyTacticalTenantId } from "@/lib/tactical/from-env";
import { withTenant } from "@/lib/tenancy";
import { getPageTenant } from "@/lib/tenancy/page";
import { env } from "@/lib/env";
import { Badge, Card, Loading, PageHeader, Stat, fmtDate } from "@/components/ui";
import { ApprovalOffNote } from "@/components/approval-off-note";
import { LiveRefresh } from "@/components/live-refresh";

type Health = Awaited<ReturnType<typeof connectorHealth>>;

/** Site connector health for the active bank (offline > 10 min = jobs wait). */
function ConnectorHealthCard({ health, directTactical }: { health: Health; directTactical: boolean }) {
  const allOnline = health.total > 0 && health.offline.length === 0;
  return (
    <Card
      title="Site connectors"
      description="Outbound-only link between this bank's Tactical sites and PatchGate"
      actions={
        <Link href="/connectors" className="flex items-center gap-1 text-xs font-medium text-primary hover:underline">
          <Cable size={14} aria-hidden /> Details
        </Link>
      }
    >
      {health.total === 0 ? (
        <p className="text-sm text-muted">
          {directTactical
            ? "No site connector yet — this bank is served by the direct Tactical link."
            : "No site connector enrolled — this bank's PCs cannot be reached until one is."}
        </p>
      ) : (
        <div className="space-y-3 text-sm">
          <div className="flex flex-wrap items-center gap-3">
            {allOnline ? <Badge tone="good">all online</Badge> : <Badge tone="bad">{`${health.offline.length} offline`}</Badge>}
            <span className="text-fg">
              {health.online} of {health.total} connector(s) online
            </span>
            <span className="text-muted">· {health.queuedJobs} job(s) queued</span>
            {health.failedJobs24h > 0 && <span className="text-danger">· {health.failedJobs24h} failed in 24 h</span>}
          </div>
          {health.offline.length > 0 && (
            <ul className="space-y-1 text-xs text-warning">
              {health.offline.map((c) => (
                <li key={c.id}>
                  {c.name}: last seen {fmtDate(c.lastSeenAt)} — jobs for its PCs wait until it reconnects.
                </li>
              ))}
            </ul>
          )}
          {health.tacticalDown.length > 0 && (
            <p className="text-xs text-danger">Tactical unreachable from: {health.tacticalDown.map((c) => c.name).join(", ")}</p>
          )}
          {health.tacticalMessagingDown.length > 0 && (
            <p className="text-xs text-danger">Tactical messaging down (no PC reachable, retrying automatically): {health.tacticalMessagingDown.map((c) => c.name).join(", ")}</p>
          )}
        </div>
      )}
    </Card>
  );
}

async function DashboardStats() {
  const { tenant } = await getPageTenant(); // per-request + auth gate + active bank
  const tenantId = tenant.id;
  // Every count is for the active bank only (explicit filter + RLS).
  const counts = await withTenant(tenantId, async (tx) => ({
    endpoints: await tx.endpoint.count({ where: { tenantId, lastScanAt: { not: null } } }),
    compliant: await tx.endpoint.count({
      where: { tenantId, lastScanAt: { not: null }, patchStates: { none: { status: "NEEDED", patch: { supersededById: null } } } },
    }),
    pendingApproval: await tx.changeRequest.count({ where: { tenantId, status: "PENDING_APPROVAL" } }),
    deploying: await tx.changeRequest.count({ where: { tenantId, status: "DEPLOYING" } }),
    criticalNeeded: await tx.endpointPatchState.count({ where: { tenantId, status: "NEEDED", patch: { severity: "CRITICAL", supersededById: null } } }),
    failed: await tx.deployment.count({ where: { tenantId, status: { in: ["FAILED", "TIMED_OUT"] } } }),
    unassigned: await tx.endpoint.count({ where: { tenantId, ringId: null } }),
  }));
  const { endpoints, compliant, pendingApproval, deploying, criticalNeeded, failed, unassigned } = counts;
  const exp = await auditExportStatus(tenantId);
  const health = await connectorHealth(tenantId);
  const directTactical = tenantId === legacyTacticalTenantId() && directTacticalConfig() !== null;
  const pct = endpoints === 0 ? null : Math.round((compliant / endpoints) * 100);
  const siemConfigured = Boolean(env().SIEM_SYSLOG_URL);
  const siemOk = siemConfigured && exp.pending === 0 && exp.minutesSinceExport !== null && exp.minutesSinceExport < 15;

  const steps = [
    unassigned > 0 && { href: "/endpoints", text: `Assign ${unassigned} PC(s) to a rollout ring — unassigned PCs are never patched.`, tone: "warn" },
    pendingApproval > 0 && { href: "/change-requests", text: `${pendingApproval} change request(s) waiting for a checker.`, tone: "info" },
    criticalNeeded > 0 && { href: "/patches?severity=CRITICAL", text: "Review missing critical patches.", tone: "bad" },
    !siemConfigured && { href: "/audit", text: "No SIEM configured — audit export is mandatory in production (set SIEM_SYSLOG_URL).", tone: "warn" },
    siemConfigured && !siemOk && { href: "/audit", text: "Audit export to the SIEM is behind — check the worker and SIEM connectivity.", tone: "bad" },
    health.offline.length > 0 && { href: "/connectors", text: `${health.offline.length} site connector(s) offline for more than 10 minutes — their jobs are waiting.`, tone: "bad" },
    health.total === 0 && !directTactical && { href: "/connectors", text: "No site connector enrolled for this bank yet.", tone: "warn" },
  ].filter(Boolean) as { href: string; text: string; tone: string }[];

  return (
    <div className="space-y-6">
      <div className="flex justify-end">
        <LiveRefresh active={deploying > 0 || health.queuedJobs > 0} />
      </div>
      <ApprovalOffNote approvalRequired={tenant.requireBankApproval} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Stat
          label="Fully patched PCs"
          value={pct === null ? "—" : `${pct}%`}
          tone={pct === null ? "neutral" : pct >= 95 ? "good" : "bad"}
          icon={<ShieldCheck size={18} />}
          hint={`${compliant} of ${endpoints} scanned`}
        />
        <Stat label="Critical gaps" value={criticalNeeded} tone={criticalNeeded > 0 ? "bad" : "good"} icon={<ShieldAlert size={18} />} hint="PC × critical patch" />
        <Stat label="Awaiting approval" value={pendingApproval} tone={pendingApproval > 0 ? "warn" : "neutral"} icon={<Clock size={18} />} />
        <Stat label="Failed deployments" value={failed} tone={failed > 0 ? "bad" : "neutral"} icon={<AlertTriangle size={18} />} />
        <Stat label="Scanned endpoints" value={endpoints} icon={<Monitor size={18} />} />
        <Stat label="Deploying now" value={deploying} icon={<Rocket size={18} />} />
        <Stat label="PCs not in a ring" value={unassigned} tone={unassigned > 0 ? "warn" : "neutral"} icon={<Waypoints size={18} />} />
        <Stat
          label="Audit → SIEM"
          value={siemConfigured ? (siemOk ? "In sync" : `${exp.pending} pending`) : "Not set up"}
          tone={siemOk ? "good" : siemConfigured ? "bad" : "warn"}
          icon={<CheckCircle2 size={18} />}
          hint={exp.minutesSinceExport === null ? "never exported" : `last export ${exp.minutesSinceExport} min ago`}
        />
      </div>

      <ConnectorHealthCard health={health} directTactical={directTactical} />

      <Card title="Next steps" description="What needs attention right now">
        {steps.length === 0 ? (
          <p className="flex items-center gap-2 text-sm text-success">
            <CheckCircle2 size={16} /> Everything is on track.
          </p>
        ) : (
          <ul className="divide-y divide-border">
            {steps.map((s) => (
              <li key={s.href}>
                <Link href={s.href} className="group flex items-center justify-between gap-4 py-3 text-sm text-fg hover:text-primary">
                  <span className="flex items-center gap-3">
                    <span
                      aria-hidden
                      className={`h-2 w-2 rounded-full ${s.tone === "bad" ? "bg-danger" : s.tone === "warn" ? "bg-warning" : "bg-info"}`}
                    />
                    {s.text}
                  </span>
                  <ArrowRight size={16} className="text-muted transition-transform group-hover:translate-x-0.5 group-hover:text-primary" />
                </Link>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}

export default function Dashboard() {
  return (
    <div>
      <PageHeader title="Patch compliance" description="Fleet health, approvals and audit export for the selected bank." />
      <Suspense fallback={<Loading />}>
        <DashboardStats />
      </Suspense>
    </div>
  );
}
