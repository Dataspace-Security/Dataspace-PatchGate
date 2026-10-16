import { Suspense } from "react";
import { canWrite } from "@/lib/auth/roles";
import { RefreshCw, ScanSearch } from "lucide-react";
import { directTacticalConfig, legacyTacticalTenantId } from "@/lib/tactical/from-env";
import { tenantUsesConnector } from "@/lib/connector/routing";
import { withTenant } from "@/lib/tenancy";
import { getPageTenant } from "@/lib/tenancy/page";
import { ActionButton } from "@/components/action-button";
import { Alert, Badge, EmptyState, Loading, PageHeader, fmtDate, rowCls, tableCls, tableWrapCls, theadCls } from "@/components/ui";
import { readWuLockDetail } from "@/lib/winupdate/wu-lock";
import { LiveRefresh } from "@/components/live-refresh";
import { formatAgo } from "@/lib/tactical/agent-times";
import { INVENTORY_JOB_TYPES, hasActiveConnectorJobs } from "@/lib/views/live-work";
import { RingSelect } from "./ring-select";

async function EndpointTable() {
  const { user, tenant } = await getPageTenant();
  const tenantId = tenant.id;
  const canEdit = canWrite(user); // auditors: read-only
  // Only the bank on the direct Tactical link can sync from it; other banks report through their connector.
  const directTactical = tenantId === legacyTacticalTenantId() && directTacticalConfig() !== null;
  // Connector banks: "Sync agents now" queues a SYNC_AGENTS job for the site connector(s).
  const connectorBank = await tenantUsesConnector(tenantId);

  const { endpoints, rings, neededCritical, inventoryRunning } = await withTenant(tenantId, async (tx) => ({
    endpoints: await tx.endpoint.findMany({
      where: { tenantId },
      orderBy: [{ site: "asc" }, { hostname: "asc" }],
      take: 500,
      include: { _count: { select: { patchStates: { where: { status: "NEEDED" } } } } },
    }),
    rings: await tx.ring.findMany({ where: { tenantId }, orderBy: { order: "asc" }, select: { id: true, name: true } }),
    neededCritical: await tx.endpointPatchState.groupBy({
      by: ["endpointId"],
      where: { tenantId, status: "NEEDED", patch: { severity: "CRITICAL", supersededById: null } },
      _count: { _all: true },
    }),
    inventoryRunning: await hasActiveConnectorJobs(tx, tenantId, INVENTORY_JOB_TYPES),
  }));
  const now = new Date();
  const critical = new Map(neededCritical.map((r) => [r.endpointId, r._count._all]));
  const unassigned = endpoints.filter((e) => !e.ringId).length;
  const notLocked = endpoints.filter((e) => e.wuLocked === false).length;

  return (
    <div className="space-y-4">
      <div className="flex justify-end">
        <LiveRefresh active={inventoryRunning} />
      </div>
      {canEdit && (
        <div className="flex flex-wrap items-start gap-2">
          {(directTactical || connectorBank) && (
            <ActionButton
              url="/api/endpoints/sync"
              label={connectorBank ? "Sync agents now" : "Sync agents from Tactical"}
              icon={<RefreshCw size={15} />}
              variant={connectorBank ? "default" : "primary"}
              showResultMessage
            />
          )}
          <ActionButton
            url="/api/endpoints/scan"
            label="Request scan of all PCs"
            icon={<ScanSearch size={15} />}
            variant={connectorBank ? "primary" : "default"}
            confirmText={connectorBank ? "Pull the PC list from Tactical now and ask every PC to rescan for updates?" : "Ask every agent to rescan for updates?"}
            showResultMessage
          />
        </div>
      )}
      {unassigned > 0 && (
        <Alert tone="warn">
          <b>{unassigned}</b> PC{unassigned === 1 ? " is" : "s are"} not in any rollout ring and will never be patched. Assign a ring below.
        </Alert>
      )}
      {notLocked > 0 && (
        <Alert tone="bad">
          <b>{notLocked}</b> PC{notLocked === 1 ? " has" : "s have"} Windows Update NOT locked and could take updates directly from Microsoft. Re-run
          Install-PatchGateAgent.ps1 on {notLocked === 1 ? "it" : "them"} (or fix the GPO): RUNBOOK “PatchGate locks Windows Update”.
        </Alert>
      )}
      {endpoints.length === 0 ? (
        <EmptyState title="No endpoints yet">
          {directTactical
            ? "Use “Sync agents from Tactical” to import the bank PCs."
            : connectorBank
              ? "No PCs reported yet — click “Request scan of all PCs” to pull them from Tactical now."
              : "PCs appear once the bank’s site connector reports its agents."}
        </EmptyState>
      ) : (
        <div className={tableWrapCls}>
          <table className={tableCls}>
            <thead className={theadCls}>
              <tr>
                <th>Hostname</th>
                <th>Branch</th>
                <th>OS / agent</th>
                <th>Ring</th>
                <th className="text-right">Missing</th>
                <th>Critical</th>
                <th>Windows Update</th>
                <th>Seen / scanned</th>
              </tr>
            </thead>
            <tbody>
              {endpoints.map((e) => {
                const crit = critical.get(e.id) ?? 0;
                return (
                  <tr key={e.id} className={rowCls}>
                    <td className="whitespace-nowrap font-medium text-fg">{e.hostname}</td>
                    <td className="whitespace-nowrap text-muted">{e.site ?? "—"}</td>
                    <td className="text-xs text-muted">
                      <div>{e.osName ?? "—"}</div>
                      {e.agentVersion && <div className="font-mono">agent {e.agentVersion}{e.goarch ? ` · ${e.goarch}` : ""}</div>}
                    </td>
                    <td>
                      <RingSelect endpointId={e.id} ringId={e.ringId} rings={rings} disabled={!canEdit} />
                    </td>
                    <td className="text-right tabular-nums">{e._count.patchStates}</td>
                    <td>{crit > 0 ? <Badge tone="bad">{`${crit} critical`}</Badge> : <Badge tone="good">none</Badge>}</td>
                    <td>
                      <WuLockCell locked={e.wuLocked} detail={e.wuLockDetail} checkedAt={e.wuLockCheckedAt} />
                    </td>
                    <td className="whitespace-nowrap text-xs text-muted">
                      <div title={`Tactical last seen: ${fmtDate(e.lastSeenAt)}`}>seen {formatAgo(e.lastSeenAt, now)}</div>
                      <div title={`Boot time: ${fmtDate(e.bootedAt)}`}>booted {formatAgo(e.bootedAt, now)}</div>
                      <div>scan {fmtDate(e.lastScanAt)}</div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

/** Windows Update lock (reported by the offline scan): green Locked / red NOT locked + the problems. */
function WuLockCell({ locked, detail, checkedAt }: { locked: boolean | null; detail: unknown; checkedAt: Date | null }) {
  if (locked === null) {
    return (
      <span title="Not reported yet: shown after the next offline Windows Update scan of this PC">
        <Badge tone="neutral">unknown</Badge>
      </span>
    );
  }
  const d = readWuLockDetail(detail);
  const outside = d.lastOutsideInstall ? `Last update Windows installed by itself (best-effort, from its history): ${d.lastOutsideInstall.title} at ${d.lastOutsideInstall.at}` : null;
  const title = [locked ? "Locked: updates only through PatchGate" : "NOT locked:", ...d.issues, outside, checkedAt ? `Checked ${fmtDate(checkedAt)}` : null]
    .filter(Boolean)
    .join("\n");
  return (
    <div title={title} className="text-xs">
      {locked ? <Badge tone="good">locked</Badge> : <Badge tone="bad">NOT locked</Badge>}
      {!locked && d.issues.length > 0 && (
        <div className="mt-1 max-w-xs text-muted">
          {d.issues[0]}
          {d.issues.length > 1 ? ` (+${d.issues.length - 1} more)` : ""}
        </div>
      )}
    </div>
  );
}

export default function EndpointsPage() {
  return (
    <div>
      <PageHeader title="Endpoints" description="Bank PCs managed through Tactical RMM. Assign each PC to a rollout ring (Test → Pilot → Production)." />
      <Suspense fallback={<Loading />}>
        <EndpointTable />
      </Suspense>
    </div>
  );
}
