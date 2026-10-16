import { Suspense } from "react";
import { Ban, Cable } from "lucide-react";
import { getPageUser } from "@/lib/auth/page-user";
import { isPlatformAdmin, isPlatformReader } from "@/lib/tenancy/policy";
import { listActiveBanks, listConnectors, listPendingEnrollments, type ConnectorView } from "@/lib/connector/admin";
import { ActionButton } from "@/components/action-button";
import { Alert, Badge, Card, EmptyState, Loading, PageHeader, fmtDate, rowCls, tableCls, tableWrapCls, theadCls } from "@/components/ui";
import { CreateEnrollmentForm, LimitsEditor } from "./connector-admin";
import { canWrite } from "@/lib/auth/roles";
import { listTacticalActivity } from "@/lib/connector/tactical-activity";
import { TacticalActivityCard } from "./tactical-activity";
import { LiveRefresh } from "@/components/live-refresh";

function fmtBytes(n: number | null | undefined): string {
  if (n === null || n === undefined) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v >= 10 || i === 0 ? Math.round(v) : v.toFixed(1)} ${units[i]}`;
}

function StatusBadge({ c }: { c: ConnectorView }) {
  if (c.status === "REVOKED") return <Badge tone="neutral">revoked</Badge>;
  return c.online ? <Badge tone="good">online</Badge> : <Badge tone="bad">offline</Badge>;
}

function TacticalCell({ c }: { c: ConnectorView }) {
  const t = c.heartbeat?.tactical;
  if (!t) return <span className="text-muted">—</span>;
  return (
    <div className="space-y-0.5">
      {t.reachable ? <Badge tone="good">reachable</Badge> : <Badge tone="bad">unreachable</Badge>}
      {typeof t.agents === "number" && <div className="text-xs text-muted">{t.agents} agents in Tactical</div>}
      {t.error && <div className="max-w-[16rem] truncate text-xs text-danger" title={t.error}>{t.error}</div>}
    </div>
  );
}

function ConnectorsTable({ rows, canAdmin, showBank }: { rows: ConnectorView[]; canAdmin: boolean; showBank: boolean }) {
  // Five grouped columns so the table fits a 1366–1440 px screen without hiding the admin actions.
  return (
    <div className={tableWrapCls}>
      <table className={tableCls}>
        <thead className={theadCls}>
          <tr>
            <th>Site</th>
            <th>Health</th>
            <th>Site cache</th>
            <th>Workload</th>
            <th>LAN limits{canAdmin ? " & actions" : ""}</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((c) => (
            <tr key={c.id} className={`${rowCls} align-top ${c.status === "REVOKED" ? "opacity-60" : ""}`}>
              <td>
                {showBank && <div className="text-xs font-medium uppercase tracking-wide text-muted">{c.tenantName}</div>}
                <div className="font-medium text-fg">{c.name}</div>
                <div className="font-mono text-[11px] text-muted">{c.id}</div>
                <div className="text-xs text-muted">version <span className="font-mono">{c.version ?? "—"}</span></div>
              </td>
              <td className="space-y-1 text-xs">
                <StatusBadge c={c} />
                <div className="whitespace-nowrap text-muted">seen {fmtDate(c.lastSeenAt)}</div>
                <TacticalCell c={c} />
              </td>
              <td className="text-xs">
                {c.heartbeat ? (
                  <>
                    <div className="text-fg">
                      {c.heartbeat.cache.files} files · {fmtBytes(c.heartbeat.cache.bytes)}
                    </div>
                    <div className="text-muted">free {fmtBytes(c.heartbeat.cache.freeBytes)}</div>
                    {c.cacheBaseUrl && <div className="max-w-[12rem] truncate font-mono text-[11px] text-muted" title={c.cacheBaseUrl}>{c.cacheBaseUrl}</div>}
                  </>
                ) : (
                  <span className="text-muted">no heartbeat yet</span>
                )}
              </td>
              <td className="text-xs tabular-nums">
                <div className="text-fg">{c.endpoints} PCs</div>
                <div className="text-muted">
                  {c.queuedJobs} queued · {c.inFlightJobs} running
                </div>
                {c.failedJobs24h > 0 && <div className="text-danger">{c.failedJobs24h} failed (24 h)</div>}
              </td>
              <td className="text-xs">
                <div>{c.maxConcurrentInstalls} concurrent installs</div>
                <div className="text-muted">{c.bandwidthLimitMbps ? `${c.bandwidthLimitMbps} Mbit/s cache cap` : "no bandwidth cap"}</div>
                {canAdmin && c.status === "ACTIVE" && (
                  <div className="mt-2 flex flex-wrap items-start gap-1.5">
                    <LimitsEditor id={c.id} maxConcurrentInstalls={c.maxConcurrentInstalls} bandwidthLimitMbps={c.bandwidthLimitMbps} />
                    <ActionButton
                      url={`/api/connector/admin/connectors/${encodeURIComponent(c.id)}/revoke`}
                      label="Revoke"
                      variant="danger"
                      askReason
                      icon={<Ban size={13} aria-hidden />}
                    />
                  </div>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

async function ConnectorsView() {
  const user = await getPageUser();
  const platform = user.tenantId === null;
  const admin = isPlatformAdmin(user);
  const rows = await listConnectors(platform ? { kind: "platform" } : { kind: "tenant", tenantId: user.tenantId! });
  // Platform auditors see the unused codes list too (hashes only, never a code); only admins create codes.
  const [banks, pending] = admin ? await Promise.all([listActiveBanks(), listPendingEnrollments()]) : platform && isPlatformReader(user) ? [[], await listPendingEnrollments()] : [[], []];
  const offline = rows.filter((c) => c.status === "ACTIVE" && !c.online);
  // Tactical seal: out-of-band activity (ADMIN + AUDITOR read; ADMIN acknowledges)
  const activity = await listTacticalActivity(platform ? { kind: "platform" } : { kind: "tenant", tenantId: user.tenantId! });

  return (
    <div className="space-y-6">
      <div className="flex justify-end">
        <LiveRefresh active={rows.some((c) => c.queuedJobs + c.inFlightJobs > 0)} />
      </div>
      {admin && <CreateEnrollmentForm banks={banks} />}
      {!admin && (
        <Alert tone="info">
          {platform ? "Read-only (auditor): only platform administrators enrol, limit or revoke connectors." : "Your bank's site connectors (read-only). Contact PatchGate support to enrol a new site."}
        </Alert>
      )}
      {activity.unacknowledged > 0 && (
        <Alert tone="bad">
          {activity.unacknowledged} action(s) in a site&apos;s Tactical outside PatchGate — see “Tactical activity” below.
        </Alert>
      )}
      {offline.length > 0 && (
        <Alert tone="warn">
          {offline.length} connector(s) offline for more than 10 minutes: {offline.map((c) => `${c.tenantName} / ${c.name}`).join(", ")}. Jobs for their PCs wait until they reconnect.
        </Alert>
      )}
      {rows.length === 0 ? (
        <EmptyState title="No site connectors yet">
          {admin ? "Create an enrolment code and run the init command on the bank site's connector host." : "No connector has been enrolled for this bank."}
        </EmptyState>
      ) : (
        <ConnectorsTable rows={rows} canAdmin={admin} showBank={platform} />
      )}
      {rows.length > 0 && <TacticalActivityCard list={activity} canAck={canWrite(user)} showBank={platform} />}
      {platform && pending.length > 0 && (
        <Card title="Unused enrolment codes" description="Codes are stored as hashes only; they expire 24 h after creation." padded={false}>
          <div className="overflow-x-auto">
          <table className={tableCls}>
            <thead className={theadCls}>
              <tr>
                <th>Bank</th>
                <th>Site</th>
                <th>Created by</th>
                <th>Expires</th>
              </tr>
            </thead>
            <tbody>
              {pending.map((p) => (
                <tr key={p.id} className={rowCls}>
                  <td>{p.tenant.name}</td>
                  <td>{p.name}</td>
                  <td className="text-xs">{p.createdBy}</td>
                  <td className="whitespace-nowrap text-xs text-muted">{fmtDate(p.expiresAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          </div>
        </Card>
      )}
    </div>
  );
}

export default function ConnectorsPage() {
  return (
    <div>
      <PageHeader
        title="Site connectors"
        description="One connector per bank site, next to its Tactical server. It only makes outbound, signed HTTPS calls to PatchGate, caches approved packages for the site's PCs and relays the bank's audit chain to its SIEM."
        actions={<Cable size={22} className="text-muted" aria-hidden />}
      />
      <Suspense fallback={<Loading />}>
        <ConnectorsView />
      </Suspense>
    </div>
  );
}
