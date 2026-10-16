import Link from "next/link";
import { Suspense } from "react";
import { RotateCcw, Trash2 } from "lucide-react";
import { getPageUser } from "@/lib/auth/page-user";
import type { SessionUser } from "@/lib/auth/session";
import { listSelectableTenants } from "@/lib/tenancy";
import { notificationsConfigured } from "@/lib/notify/deliver";
import { PLATFORM_SCOPE, getMyOptOuts, getNotificationSettings, listOutbox, outboxCounts, type OutboxFilter } from "@/lib/notify/settings";
import { ActionButton } from "@/components/action-button";
import { Alert, Badge, Card, EmptyState, Loading, PageHeader, fmtDate, rowCls, tableCls, tableWrapCls, theadCls } from "@/components/ui";
import { AddWebhookForm, EventTogglesForm, OptOutToggles } from "./notification-forms";

type SearchParams = Promise<Record<string, string | string[] | undefined>>;

const STATUS_TONE = { PENDING: "warn", SENDING: "busy", SENT: "good", DEAD: "bad", SKIPPED: "neutral" } as const;

function first(v: string | string[] | undefined): string | undefined {
  return Array.isArray(v) ? v[0] : v;
}

async function ScopeSettings({ user, scope }: { user: SessionUser; scope: string }) {
  const s = await getNotificationSettings(user, scope);
  return (
    <Card title={`Notification settings — ${s.scopeName}`} description={s.updatedAt ? `Last changed ${fmtDate(s.updatedAt)} by ${s.updatedBy ?? "—"}` : "Defaults: every event on, no webhooks."}>
      <div className="space-y-6">
        <div className="space-y-3">
          <h3 className="text-sm font-semibold text-fg">Webhooks (Teams / Slack)</h3>
          {s.webhooks.length === 0 ? (
            <p className="text-sm text-muted">No webhooks configured.</p>
          ) : (
            <ul className="divide-y divide-border rounded-lg border border-border">
              {s.webhooks.map((w) => (
                <li key={w.id} className="flex items-center justify-between gap-3 px-3 py-2">
                  <span className="font-mono text-xs text-fg">{w.display}</span>
                  <ActionButton
                    url="/api/notifications/settings"
                    body={{ scope, action: "remove-webhook", id: w.id }}
                    label="Remove"
                    confirmText="Remove this webhook?"
                    icon={<Trash2 size={14} />}
                  />
                </li>
              ))}
            </ul>
          )}
          <AddWebhookForm scope={scope} hosts={s.webhookHosts} />
        </div>
        <div className="space-y-3">
          <h3 className="text-sm font-semibold text-fg">Events</h3>
          <EventTogglesForm key={`${scope}-${s.updatedAt?.toISOString() ?? "new"}`} scope={scope} events={s.events} />
        </div>
      </div>
    </Card>
  );
}

async function Outbox({ user, filter }: { user: SessionUser; filter: OutboxFilter }) {
  const [counts, rows] = await Promise.all([outboxCounts(user), listOutbox(user, filter)]);
  const tab = (f: OutboxFilter, label: string) => (
    <Link
      href={`/settings/notifications?outbox=${f}`}
      aria-current={f === filter ? "page" : undefined}
      className="rounded-md px-2.5 py-1 text-xs font-medium text-muted hover:text-fg aria-[current=page]:bg-surface aria-[current=page]:text-fg aria-[current=page]:shadow-sm"
    >
      {label}
    </Link>
  );
  return (
    <Card
      title="Outbox"
      description={Object.entries(counts).map(([k, v]) => `${k.toLowerCase()} ${v}`).join(" · ") || "empty"}
      actions={
        <div className="flex gap-1 rounded-lg bg-surface-2 p-0.5">
          {tab("recent", "Recent")}
          {tab("failed", "Failed / retrying")}
        </div>
      }
      padded={false}
    >
      {rows.length === 0 ? (
        <div className="p-5">
          <EmptyState title="Nothing here" />
        </div>
      ) : (
        <div className={tableWrapCls + " rounded-none border-0 shadow-none"}>
          <table className={tableCls}>
            <thead className={theadCls}>
              <tr>
                <th>Created</th>
                <th>Event</th>
                <th>To</th>
                <th>Status</th>
                <th>Attempts</th>
                <th>Last error</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id} className={rowCls}>
                  <td className="whitespace-nowrap text-xs text-muted">{fmtDate(r.createdAt)}</td>
                  <td>
                    <div className="text-sm text-fg">{r.subject}</div>
                    <div className="text-xs text-muted">
                      {r.event} · {r.bank ?? "platform"} · {r.severity}
                    </div>
                  </td>
                  <td className="font-mono text-xs">
                    {r.channel === "EMAIL" ? "✉ " : "⇢ "}
                    {r.target}
                  </td>
                  <td>
                    <Badge tone={STATUS_TONE[r.status as keyof typeof STATUS_TONE] ?? "neutral"}>{r.status}</Badge>
                    {r.status === "PENDING" && r.attempts > 0 && <div className="mt-1 text-xs text-muted">next {fmtDate(r.nextAttemptAt)}</div>}
                  </td>
                  <td className="tabular-nums">{r.attempts}</td>
                  <td className="max-w-xs text-xs text-muted">{r.lastError ?? "—"}</td>
                  <td className="text-right">
                    {(r.status === "DEAD" || r.status === "SKIPPED") && (
                      <ActionButton url={`/api/notifications/${r.id}/retry`} label="Retry" icon={<RotateCcw size={14} />} />
                    )}
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

async function NotificationsContent({ searchParams }: { searchParams: SearchParams }) {
  const sp = await searchParams;
  const user = await getPageUser();
  const platformAdmin = user.tenantId === null && user.role === "ADMIN";
  const isAdmin = user.role === "ADMIN";
  const optOuts = await getMyOptOuts(user);
  const requested = first(sp.scope);
  const scope = user.tenantId ?? (requested && requested.length <= 64 ? requested : PLATFORM_SCOPE);
  const banks = platformAdmin ? await listSelectableTenants() : [];
  const outboxFilter: OutboxFilter = first(sp.outbox) === "failed" ? "failed" : "recent";

  return (
    <div className="space-y-6">
      {!notificationsConfigured() && (
        <Alert tone="warn">E-mail delivery is not configured (SMTP_URL / SMTP_FROM). Notifications are recorded in the outbox and skipped.</Alert>
      )}
      <Card title="My notifications" description={`E-mails go to ${user.upn}. Critical notices (security, integrity) are always sent.`}>
        <OptOutToggles items={optOuts} />
      </Card>

      {isAdmin && (
        <>
          {platformAdmin && (
            <nav aria-label="Settings scope" className="flex flex-wrap items-center gap-2 text-sm">
              <span className="text-muted">Settings for:</span>
              {[{ id: PLATFORM_SCOPE, name: "PatchGate platform" }, ...banks].map((b) => (
                <Link
                  key={b.id}
                  href={`/settings/notifications?scope=${encodeURIComponent(b.id)}`}
                  aria-current={b.id === scope ? "page" : undefined}
                  className="rounded-full border border-border px-3 py-1 text-xs font-medium text-muted hover:text-fg aria-[current=page]:border-primary aria-[current=page]:text-fg"
                >
                  {b.name}
                </Link>
              ))}
            </nav>
          )}
          <ScopeSettings user={user} scope={scope} />
        </>
      )}

      {platformAdmin && <Outbox user={user} filter={outboxFilter} />}
    </div>
  );
}

export default function NotificationSettingsPage({ searchParams }: { searchParams: SearchParams }) {
  return (
    <div>
      <PageHeader title="Notifications" description="E-mail and Teams / Slack webhook alerts for approvals, failed rollouts, offline connectors, held packages and integrity problems." />
      <Suspense fallback={<Loading />}>
        <NotificationsContent searchParams={searchParams} />
      </Suspense>
    </div>
  );
}
