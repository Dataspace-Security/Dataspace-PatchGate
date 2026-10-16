import { Suspense } from "react";
import { RefreshCw, ScanSearch } from "lucide-react";
import { directTacticalConfig, legacyTacticalTenantId } from "@/lib/tactical/from-env";
import { withTenant } from "@/lib/tenancy";
import { getPageTenant } from "@/lib/tenancy/page";
import { ActionButton } from "@/components/action-button";
import { Alert, Badge, EmptyState, Loading, PageHeader, fmtDate, rowCls, tableCls, tableWrapCls, theadCls } from "@/components/ui";
import { RingSelect } from "./ring-select";

async function EndpointTable() {
  const { user, tenant } = await getPageTenant();
  const tenantId = tenant.id;
  const canEdit = user.role !== "VIEWER";
  // Only the bank on the direct Tactical link can sync from it; other banks report through their connector.
  const directTactical = tenantId === legacyTacticalTenantId() && directTacticalConfig() !== null;

  const { endpoints, rings, neededCritical } = await withTenant(tenantId, async (tx) => ({
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
  }));
  const critical = new Map(neededCritical.map((r) => [r.endpointId, r._count._all]));
  const unassigned = endpoints.filter((e) => !e.ringId).length;

  return (
    <div className="space-y-4">
      {canEdit && (
        <div className="flex flex-wrap items-start gap-2">
          {directTactical && (
            <ActionButton url="/api/endpoints/sync" label="Sync agents from Tactical" icon={<RefreshCw size={15} />} variant="primary" />
          )}
          <ActionButton
            url="/api/endpoints/scan"
            label="Request scan of all PCs"
            icon={<ScanSearch size={15} />}
            confirmText="Ask every agent to rescan for updates?"
          />
        </div>
      )}
      {unassigned > 0 && (
        <Alert tone="warn">
          <b>{unassigned}</b> PC{unassigned === 1 ? " is" : "s are"} not in any rollout ring and will never be patched. Assign a ring below.
        </Alert>
      )}
      {endpoints.length === 0 ? (
        <EmptyState title="No endpoints yet">
          {directTactical ? "Use “Sync agents from Tactical” to import the bank PCs." : "PCs appear once the bank’s site connector reports its agents."}
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
                <th>Last scan</th>
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
                    <td className="whitespace-nowrap text-xs text-muted">{fmtDate(e.lastScanAt)}</td>
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
