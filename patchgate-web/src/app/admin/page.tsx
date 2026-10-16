import { Suspense } from "react";
import Link from "next/link";
import { Building2, KeyRound, Lock, ShieldAlert, Users } from "lucide-react";
import { prisma } from "@/lib/db";
import { recentAdminEvents } from "@/lib/auth/admin-overview";
import { Badge, Card, EmptyState, Loading, PageHeader, Stat, fmtDate, rowCls, tableCls, tableWrapCls, theadCls } from "@/components/ui";
import { AdminTabs, getAdminUser } from "./admin-guard";

async function Overview() {
  const { user, denied, readOnly: auditor } = await getAdminUser();
  if (denied) return denied;
  const platform = user.tenantId === null;
  // Accounts are managed by platform admins only: for every bank user the Users list is read-only.
  const readOnly = auditor || !platform;
  const scope = platform ? {} : { tenantId: user.tenantId };
  const now = new Date();

  const [total, active, locked, pendingMfa, mustChange, banks, tenant, recent] = await Promise.all([
    prisma.user.count({ where: scope }),
    prisma.user.count({ where: { ...scope, active: true } }),
    prisma.user.count({ where: { ...scope, lockedUntil: { gt: now } } }),
    prisma.user.count({ where: { ...scope, active: true, totpEnabled: false, passwordHash: { not: null } } }),
    prisma.user.count({ where: { ...scope, active: true, mustChangePassword: true } }),
    platform ? prisma.tenant.count({ where: { active: true } }) : Promise.resolve(0),
    platform ? Promise.resolve(null) : prisma.tenant.findUnique({ where: { id: user.tenantId! }, select: { name: true } }),
    recentAdminEvents(user.tenantId),
  ]);

  return (
    <>
      <PageHeader
        title="Administration"
        description={
          platform
            ? "Platform administration: banks, our team and every bank's users."
            : `Bank administration for ${tenant?.name ?? "your bank"}: your bank's PatchGate users (accounts are managed by PatchGate).`
        }
      />
      <AdminTabs active="overview" platform={platform} />
      <div className="space-y-6">
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <Stat label="Active users" value={active} hint={`${total} in total`} icon={<Users size={16} />} />
          {platform && <Stat label="Active banks" value={banks} icon={<Building2 size={16} />} />}
          <Stat label="Locked out" value={locked} tone={locked > 0 ? "warn" : "neutral"} icon={<Lock size={16} />} hint="5 failed attempts → 15 min" />
          <Stat label="MFA not set up" value={pendingMfa} tone={pendingMfa > 0 ? "warn" : "neutral"} icon={<ShieldAlert size={16} />} hint="enrol at next sign-in" />
          {!platform && <Stat label="Temporary password" value={mustChange} icon={<KeyRound size={16} />} hint="must change at next sign-in" />}
        </div>

        <div className="grid gap-4 md:grid-cols-2">
          <Card title="Users" description={readOnly ? "Every account in your scope, with role, status and last sign-in (read-only)." : "Create accounts, change roles, reset passwords or authenticators, deactivate leavers."}>
            <Link href="/admin/users" className="text-sm font-medium text-primary hover:underline">
              {readOnly ? "View users →" : "Manage users →"}
            </Link>
          </Card>
          {platform ? (
            <Card title="Banks" description={readOnly ? "Every client bank and its status (read-only)." : "Onboard banks, suspend a bank."}>
              <Link href="/admin/banks" className="text-sm font-medium text-primary hover:underline">
                {readOnly ? "View banks →" : "Manage banks →"}
              </Link>
            </Card>
          ) : (
            <Card title="Security policy" description="Applies to every PatchGate account.">
              <ul className="list-disc space-y-1 pl-5 text-sm text-muted">
                <li>Passwords of at least 14 characters, plus an authenticator app (TOTP).</li>
                <li>Accounts lock for 15 minutes after 5 failed attempts.</li>
                <li>Sessions end after 15 minutes idle and 8 hours at most.</li>
              </ul>
            </Card>
          )}
        </div>

        <section className="space-y-3">
          <h2 className="text-sm font-semibold text-fg">Recent administrative events</h2>
          {recent.length === 0 ? (
            <EmptyState title="Nothing yet">User and bank changes will appear here (full history in the audit log).</EmptyState>
          ) : (
            <div className={tableWrapCls}>
              <table className={tableCls}>
                <thead className={theadCls}>
                  <tr>
                    <th>When</th>
                    <th>By</th>
                    <th>Event</th>
                    <th>Subject</th>
                  </tr>
                </thead>
                <tbody>
                  {recent.map((e) => {
                    const p = (e.payload ?? {}) as Record<string, unknown>;
                    const subject = typeof p.upn === "string" ? p.upn : typeof p.slug === "string" ? p.slug : "—";
                    return (
                      <tr key={e.seq.toString()} className={rowCls}>
                        <td className="whitespace-nowrap text-xs text-muted">{fmtDate(e.ts)}</td>
                        <td className="font-mono text-xs">{e.actor}</td>
                        <td>
                          <Badge tone={e.action === "auth.lockout" || e.action === "user.deactivated" ? "warn" : "info"}>{e.action.replace(".", " · ")}</Badge>
                        </td>
                        <td className="font-mono text-xs text-muted">{subject}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>
    </>
  );
}

export default function AdminPage() {
  return (
    <Suspense fallback={<Loading />}>
      <Overview />
    </Suspense>
  );
}
