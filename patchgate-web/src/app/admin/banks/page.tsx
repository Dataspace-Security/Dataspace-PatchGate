import { Suspense } from "react";
import { listTenants } from "@/lib/auth/admin-service";
import { Alert, Badge, EmptyState, Loading, PageHeader, fmtDate, rowCls, tableCls, tableWrapCls, theadCls } from "@/components/ui";
import { AdminTabs, getAdminUser } from "../admin-guard";
import { BankRowActions, CreateBankForm } from "./bank-admin";

async function BanksTable() {
  const { user, denied, readOnly } = await getAdminUser();
  if (denied) return denied;
  if (user.tenantId !== null) {
    return (
      <>
        <PageHeader title="Banks" />
        <AdminTabs active="banks" platform={false} />
        <Alert tone="bad">Only PatchGate platform staff see the list of banks.</Alert>
      </>
    );
  }
  const banks = await listTenants(user);

  return (
    <>
      <PageHeader title="Banks" description="Client banks hosted on this PatchGate. Deactivating a bank signs all of its users out and blocks their sign-in." />
      <AdminTabs active="banks" platform />
      <div className="space-y-6">
        {readOnly ? <Alert tone="info">Read-only view (auditor).</Alert> : <CreateBankForm />}
        {banks.length === 0 ? (
          <EmptyState title="No banks yet">Onboard the first bank with “New bank”.</EmptyState>
        ) : (
          <div className={tableWrapCls}>
            <table className={tableCls}>
              <thead className={theadCls}>
                <tr>
                  <th>Bank</th>
                  <th>Short code</th>
                  <th>Status</th>
                  <th>Change approval</th>
                  <th className="text-right">Users</th>
                  <th>Created</th>
                  {!readOnly && <th className="text-right">Actions</th>}
                </tr>
              </thead>
              <tbody>
                {banks.map((b) => (
                  <tr key={b.id} className={`${rowCls} ${b.active ? "" : "opacity-60"}`}>
                    <td className="font-medium text-fg">{b.name}</td>
                    <td className="font-mono text-xs">{b.slug}</td>
                    <td>{b.active ? <Badge tone="good">active</Badge> : <Badge tone="neutral">inactive</Badge>}</td>
                    <td className="text-sm">
                      {b.requireBankApproval ? <Badge tone="info">approval ON</Badge> : <Badge tone="warn">approval OFF</Badge>}
                    </td>
                    <td className="text-right tabular-nums">{b._count.users}</td>
                    <td className="whitespace-nowrap text-xs text-muted">{fmtDate(b.createdAt)}</td>
                    {!readOnly && (
                      <td className="text-right">
                        <BankRowActions bank={{ id: b.id, name: b.name, slug: b.slug, active: b.active, requireBankApproval: b.requireBankApproval }} />
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  );
}

export default function AdminBanksPage() {
  return (
    <Suspense fallback={<Loading />}>
      <BanksTable />
    </Suspense>
  );
}
