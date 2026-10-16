import { Suspense } from "react";
import { listTenants, listUsers } from "@/lib/auth/admin-service";
import { Badge, EmptyState, Loading, PageHeader, fmtDate, rowCls, tableCls, tableWrapCls, theadCls } from "@/components/ui";
import { AdminTabs, ROLE_LABEL, getAdminUser } from "../admin-guard";
import { CreateUserForm, UserActions } from "./user-admin";

async function UsersTable() {
  const { user: actor, denied } = await getAdminUser();
  if (denied) return denied;
  const platform = actor.tenantId === null;
  const [users, tenants] = await Promise.all([listUsers(actor), listTenants(actor)]);
  const now = new Date();
  const bankOptions = tenants.map((t) => ({ id: t.id, name: t.name, active: t.active }));

  return (
    <>
      <PageHeader
        title="Users"
        description={
          platform
            ? "Every PatchGate account — our team and all banks. New users get a one-time temporary password and set up an authenticator at first sign-in."
            : "Accounts of your bank. New users get a one-time temporary password and set up an authenticator at first sign-in."
        }
      />
      <AdminTabs active="users" platform={platform} />
      <div className="space-y-6">
        <CreateUserForm platform={platform} banks={bankOptions} ownBankName={platform ? null : (tenants[0]?.name ?? null)} />
        {users.length === 0 ? (
          <EmptyState title="No users yet" />
        ) : (
          <div className={tableWrapCls}>
            <table className={tableCls}>
              <thead className={theadCls}>
                <tr>
                  <th>User</th>
                  {platform && <th>Bank</th>}
                  <th>Role</th>
                  <th>Status</th>
                  <th>Last sign-in</th>
                  <th className="text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {users.map((u) => {
                  const locked = u.lockedUntil !== null && u.lockedUntil > now;
                  const self = u.id === actor.id;
                  return (
                    <tr key={u.id} className={`${rowCls} ${u.active ? "" : "opacity-60"}`}>
                      <td>
                        <div className="font-medium text-fg">
                          {u.name}
                          {self && <span className="ml-2 text-xs font-normal text-muted">(you)</span>}
                        </div>
                        <div className="font-mono text-xs text-muted">{u.upn}</div>
                      </td>
                      {platform && <td className="whitespace-nowrap text-sm">{u.tenantName ?? <span className="font-medium text-primary">PatchGate team</span>}</td>}
                      <td className="whitespace-nowrap text-sm">{ROLE_LABEL[u.role]}</td>
                      <td>
                        <div className="flex flex-wrap gap-1">
                          {u.active ? <Badge tone="good">active</Badge> : <Badge tone="neutral">deactivated</Badge>}
                          {locked && <Badge tone="bad">locked</Badge>}
                          {u.active && !u.totpEnabled && u.hasPassword && <Badge tone="warn">MFA pending</Badge>}
                          {u.active && u.mustChangePassword && <Badge tone="info">temp password</Badge>}
                          {!u.hasPassword && <Badge tone="neutral">SSO only</Badge>}
                        </div>
                      </td>
                      <td className="whitespace-nowrap text-xs text-muted">{fmtDate(u.lastLoginAt)}</td>
                      <td className="text-right">
                        <UserActions
                          user={{ id: u.id, upn: u.upn, name: u.name, role: u.role, active: u.active, locked }}
                          self={self}
                          canResetCredentials={platform || u.role === "VIEWER" || u.role === "OPERATOR"}
                        />
                      </td>
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

export default function AdminUsersPage() {
  return (
    <Suspense fallback={<Loading />}>
      <UsersTable />
    </Suspense>
  );
}
