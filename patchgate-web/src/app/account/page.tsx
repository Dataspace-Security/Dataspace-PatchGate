import { Suspense, type ReactNode } from "react";
import { cookies } from "next/headers";
import { getPageUser } from "@/lib/auth/page-user";
import { getAccountOverview } from "@/lib/auth/account-service";
import { SESSION_COOKIE, sha256Hex } from "@/lib/auth/tokens";
import { authMode, env } from "@/lib/env";
import { PASSWORD_MIN } from "@/lib/auth/password";
import { ROLE_LABEL, roleDescription } from "@/lib/auth/roles";
import { Alert, Badge, Card, Loading, PageHeader, fmtDate, rowCls, tableCls, tableWrapCls, theadCls } from "@/components/ui";
import { ChangePasswordForm, RevokeOthersButton } from "./account-forms";


function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <dt className="text-xs font-medium uppercase tracking-wide text-muted">{label}</dt>
      <dd className="mt-1 text-sm text-fg">{children}</dd>
    </div>
  );
}

async function Account() {
  const user = await getPageUser();
  const e = env();
  const mode = authMode(e);
  const token = (await cookies()).get(SESSION_COOKIE)?.value;
  const overview = await getAccountOverview(user.id, token ? sha256Hex(token) : null, e.SESSION_IDLE_MINUTES);
  if (!overview) return <Alert tone="bad">Your account could not be loaded.</Alert>;
  const others = overview.sessions.filter((s) => !s.current).length;

  return (
    <>
      <PageHeader title="My account" description="Your PatchGate identity, password and active sessions." />
      <div className="space-y-6">
        <Card title="Signed in as">
          <dl className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <Field label="Username">
              <span className="font-mono">{overview.upn}</span>
            </Field>
            <Field label="Role">
              <span title={roleDescription(overview.role, overview.bankName ? "bank" : "platform")}>{ROLE_LABEL[overview.role]}</span>
              <span className="mt-0.5 block text-xs text-muted">{roleDescription(overview.role, overview.bankName ? "bank" : "platform")}</span>
            </Field>
            <Field label="Organisation">{overview.bankName ?? "PatchGate team"}</Field>
            <Field label="Last sign-in">{fmtDate(overview.lastLoginAt)}</Field>
          </dl>
        </Card>

        {mode === "local" && overview.hasPassword ? (
          <Card title="Change password" description={`At least ${PASSWORD_MIN} characters; not your username or a common password. All your other sessions are signed out.`}>
            <p className="mb-4 text-xs text-muted">Password last changed: {fmtDate(overview.passwordChangedAt)}</p>
            <ChangePasswordForm minLength={PASSWORD_MIN} upn={overview.upn} />
          </Card>
        ) : (
          <Card title="Password">
            <Alert tone="info">
              {mode === "oidc"
                ? "You sign in through your organisation's single sign-on. Your password and second factor are managed by your identity provider, not by PatchGate."
                : mode === "dev"
                  ? "Development sign-in: no PatchGate password is used in this mode."
                  : "This account has no PatchGate password."}
            </Alert>
          </Card>
        )}

        <Card
          title="Active sessions"
          description="Sessions end after the idle timeout or the absolute session limit."
          actions={mode === "local" ? <RevokeOthersButton disabled={others === 0} /> : undefined}
        >
          {overview.sessions.length === 0 ? (
            <p className="text-sm text-muted">No server-side sessions{mode === "dev" ? " (development sign-in)" : ""}.</p>
          ) : (
            <div className={tableWrapCls}>
              <table className={tableCls}>
                <thead className={theadCls}>
                  <tr>
                    <th>Started</th>
                    <th>Last activity</th>
                    <th>Address</th>
                    <th>Browser</th>
                  </tr>
                </thead>
                <tbody>
                  {overview.sessions.map((s, i) => (
                    <tr key={i} className={rowCls}>
                      <td>
                        {fmtDate(s.createdAt)} {s.current && <Badge tone="good">this session</Badge>}
                      </td>
                      <td>{fmtDate(s.lastSeenAt)}</td>
                      <td className="font-mono text-xs">{s.ip ?? "—"}</td>
                      <td className="max-w-xs truncate text-xs text-muted" title={s.userAgent ?? undefined}>
                        {s.userAgent ?? "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>
    </>
  );
}

export default function AccountPage() {
  return (
    <Suspense fallback={<Loading />}>
      <Account />
    </Suspense>
  );
}
