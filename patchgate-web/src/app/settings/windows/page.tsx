import { Suspense } from "react";
import { getBankPolicy } from "@/lib/policies/bank-settings";
import { listRings } from "@/lib/policies/rings";
import { listWindows, previewWindow } from "@/lib/policies/windows";
import { REBOOT_LABEL } from "@/lib/policies/reboot-labels";
import { Badge, EmptyState, Loading, PageHeader, rowCls, tableCls, tableWrapCls, theadCls } from "@/components/ui";
import { isPlatformReader } from "@/lib/auth/roles";
import { ReadOnlyNotice, SettingsTabs, getSettingsContext } from "../settings-shell";
import { WindowEditor } from "./window-forms";

async function Windows() {
  const { user, tenant, denied, readOnly } = await getSettingsContext();
  const header = (
    <>
      <PageHeader
        title="Maintenance windows"
        description="When a ring may be patched: a cron start time (5 fields, in the window's timezone) plus a duration. Previews are shown in the bank's timezone."
      />
      <SettingsTabs active="windows" platformAdmin={isPlatformReader(user)} />
    </>
  );
  if (denied) return <>{header}{denied}</>;

  const [windows, rings, policy] = await Promise.all([listWindows(tenant.id), listRings(tenant.id), getBankPolicy(tenant.id)]);
  const ringOptions = rings.map((r) => ({ id: r.id, name: r.name }));
  const now = new Date();

  return (
    <>
      {header}
      <div className="space-y-6">
        {readOnly ? <ReadOnlyNotice /> : <WindowEditor rings={ringOptions} bankTimezone={policy.timezone} />}
        {windows.length === 0 ? (
          <EmptyState title="No maintenance windows">Without a window a ring&apos;s approved changes deploy as soon as they are started.</EmptyState>
        ) : (
          <div className={tableWrapCls}>
            <table className={tableCls}>
              <thead className={theadCls}>
                <tr>
                  <th>Window</th>
                  <th>Ring</th>
                  <th>Schedule</th>
                  <th>Reboot</th>
                  <th>Next start ({policy.timezone})</th>
                  <th className="text-right">Change requests</th>
                  {!readOnly && <th className="text-right">Actions</th>}
                </tr>
              </thead>
              <tbody>
                {windows.map((w) => {
                  const next = previewWindow(w, policy.timezone, now)[0];
                  return (
                    <tr key={w.id} className={rowCls}>
                      <td className="font-medium text-fg">{w.name}</td>
                      <td className="whitespace-nowrap">{w.ring.name}</td>
                      <td className="whitespace-nowrap font-mono text-xs">
                        {w.cron} · {w.durationMin} min · {w.timezone}
                      </td>
                      <td><Badge tone="neutral">{REBOOT_LABEL[w.rebootPolicy]}</Badge></td>
                      <td className="whitespace-nowrap text-xs">{next ? next.startLocal : <span className="text-danger">invalid schedule</span>}</td>
                      <td className="text-right tabular-nums">{w._count.changeRequests}</td>
                      {!readOnly && (
                        <td className="text-right">
                          <WindowEditor
                            rings={ringOptions}
                            bankTimezone={policy.timezone}
                            existing={{ id: w.id, name: w.name, ringId: w.ringId, cron: w.cron, durationMin: w.durationMin, timezone: w.timezone, rebootPolicy: w.rebootPolicy, inUse: w._count.changeRequests > 0 }}
                          />
                        </td>
                      )}
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  );
}

export default function WindowsSettingsPage() {
  return (
    <Suspense fallback={<Loading />}>
      <Windows />
    </Suspense>
  );
}
