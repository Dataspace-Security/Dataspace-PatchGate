import { Suspense } from "react";
import { withTenant } from "@/lib/tenancy";
import { listRings } from "@/lib/policies/rings";
import { REBOOT_LABEL } from "@/lib/policies/reboot-labels";
import { Badge, Loading, PageHeader, rowCls, tableCls, tableWrapCls, theadCls } from "@/components/ui";
import { isPlatformReader } from "@/lib/auth/roles";
import { ReadOnlyNotice, SettingsTabs, getSettingsContext } from "../settings-shell";
import { BulkAssignPanel, CreateRingForm, RingRowActions } from "./ring-forms";

async function Rings() {
  const { user, tenant, denied, readOnly } = await getSettingsContext();
  const header = (
    <>
      <PageHeader
        title="Rollout rings"
        description={`Rings of ${tenant.name}, in rollout order (test first). A ring can be deleted only when it has no endpoints and no change requests.`}
      />
      <SettingsTabs active="rings" platformAdmin={isPlatformReader(user)} />
    </>
  );
  if (denied) return <>{header}{denied}</>;

  const [rings, sites] = await Promise.all([
    listRings(tenant.id),
    withTenant(tenant.id, (tx) => tx.endpoint.findMany({ where: { tenantId: tenant.id, site: { not: null } }, distinct: ["site"], select: { site: true }, orderBy: { site: "asc" }, take: 500 })),
  ]);
  const ringOptions = rings.map((r) => ({ id: r.id, name: r.name }));

  return (
    <>
      {header}
      <div className="space-y-6">
        {readOnly ? <ReadOnlyNotice /> : <CreateRingForm />}
        <div className={tableWrapCls}>
          <table className={tableCls}>
            <thead className={theadCls}>
              <tr>
                <th>#</th>
                <th>Ring</th>
                <th>WSUS group</th>
                <th>Reboot default</th>
                <th className="text-right">Endpoints</th>
                <th className="text-right">Windows</th>
                <th className="text-right">Change requests</th>
                {!readOnly && <th className="text-right">Actions</th>}
              </tr>
            </thead>
            <tbody>
              {rings.map((r, i) => (
                <tr key={r.id} className={rowCls}>
                  <td className="tabular-nums text-muted">{i + 1}</td>
                  <td className="font-medium text-fg">{r.name}</td>
                  <td className="font-mono text-xs">{r.wsusGroup}</td>
                  <td>{r.rebootPolicy ? <Badge tone="info">{REBOOT_LABEL[r.rebootPolicy]}</Badge> : <span className="text-xs text-muted">bank default</span>}</td>
                  <td className="text-right tabular-nums">{r._count.endpoints}</td>
                  <td className="text-right tabular-nums">{r._count.windows}</td>
                  <td className="text-right tabular-nums">{r._count.changeRequests}</td>
                  {!readOnly && (
                    <td className="text-right">
                      <RingRowActions
                        ring={{ id: r.id, name: r.name, wsusGroup: r.wsusGroup, rebootPolicy: r.rebootPolicy, deletable: r._count.endpoints === 0 && r._count.changeRequests === 0 }}
                        order={rings.map((x) => x.id)}
                        index={i}
                      />
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {!readOnly && <BulkAssignPanel rings={ringOptions} sites={sites.flatMap((s) => (s.site ? [s.site] : []))} />}
      </div>
    </>
  );
}

export default function RingsSettingsPage() {
  return (
    <Suspense fallback={<Loading />}>
      <Rings />
    </Suspense>
  );
}
