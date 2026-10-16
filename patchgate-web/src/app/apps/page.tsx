import { Suspense } from "react";
import { CheckCircle2, MinusCircle, PlusCircle, ShieldQuestion, XCircle } from "lucide-react";
import { prisma } from "@/lib/db";
import { getPageUser } from "@/lib/auth/page-user";
import { isPlatformAdmin, isPlatformUser, resolveActiveTenant, withTenant } from "@/lib/tenancy";
import { ActionButton } from "@/components/action-button";
import { Badge, Card, EmptyState, Loading, PageHeader, fmtDate, rowCls, tableCls, theadCls } from "@/components/ui";
import { listAllowlistRequests } from "@/lib/discovery/service";
import { AddAppForm } from "./add-app-form";

async function AppsContent() {
  const user = await getPageUser();
  // Shared catalog page: works without a bank; the per-bank opt-in column needs the active bank.
  const tenant = await resolveActiveTenant(user);
  const platformStaff = isPlatformUser(user);
  // Trust decisions and the shared allow-list are ours (platform admins), never a bank admin's.
  const isAdmin = isPlatformAdmin(user);
  const canToggleBank = user.role === "ADMIN" && tenant !== null;
  const now = new Date();

  const [held, apps, mirrors, runs] = await Promise.all([
    platformStaff
      ? prisma.appVersion.findMany({ where: { verification: "HELD" }, include: { app: true }, orderBy: { createdAt: "asc" } })
      : Promise.resolve([]),
    prisma.app.findMany({
      orderBy: { displayName: "asc" },
      include: { versions: { orderBy: { createdAt: "desc" }, take: 3 } },
    }),
    prisma.mirroredRelease.findMany({ orderBy: [{ component: "asc" }, { createdAt: "desc" }], take: 30 }),
    platformStaff ? prisma.fetchRun.findMany({ orderBy: { startedAt: "desc" }, take: 15 }) : Promise.resolve([]),
  ]);
  // Banks' "Manage" of a product that is not on the shared list yet: decided by platform admins only.
  const requests = isAdmin ? await listAllowlistRequests() : [];
  const enabled = tenant
    ? new Set((await withTenant(tenant.id, (tx) => tx.tenantApp.findMany({ where: { tenantId: tenant.id }, select: { appId: true } }))).map((r) => r.appId))
    : null;

  return (
    <div className="space-y-6">
      {requests.length > 0 && (
        <Card
          title={`Allow-list requests from banks (${requests.length})`}
          description="A bank admin asked PatchGate to patch a product that is not on the shared allow-list. Approving adds it for EVERY bank's fetcher (no signer pin: the first download is held for your signer decision) and enables it for the requesting bank."
          padded={false}
        >
          <ul className="divide-y divide-border">
            {requests.map((r) => (
              <li key={r.id} className="flex flex-col gap-3 p-4 lg:flex-row lg:items-center lg:justify-between">
                <div className="min-w-0 space-y-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-medium">{r.displayName}</span>
                    <span className="font-mono text-xs">{r.wingetId}</span>
                    <Badge tone="info">{r.tenantName}</Badge>
                  </div>
                  <p className="text-xs text-muted">
                    {r.publisher ?? "unknown publisher"} · on {r.endpointCount} PCs · requested by {r.requestedBy ?? "?"} on {fmtDate(r.requestedAt)}
                  </p>
                </div>
                <div className="flex gap-2">
                  <ActionButton url={`/api/discovery/${r.id}/approve`} label="Approve" variant="primary" icon={<CheckCircle2 size={15} />} confirmText={`Add ${r.wingetId} to the shared allow-list and enable it for ${r.tenantName}?`} />
                  <ActionButton url={`/api/discovery/${r.id}/decline`} label="Decline" icon={<XCircle size={15} />} askReason />
                </div>
              </li>
            ))}
          </ul>
        </Card>
      )}
      {held.length > 0 && (
        <Card
          title={`Held for decision (${held.length})`}
          description="Downloaded and checked, but NOT served to any PC until an admin decides. Approving pins the signer organisation for future automatic updates."
          padded={false}
        >
          <ul className="divide-y divide-border">
            {held.map((v) => {
              const why = HOLD_TEXT[v.holdReason ?? "FIRST_SIGNER"];
              return (
                <li key={v.id} className="flex flex-col gap-3 p-4 lg:flex-row lg:items-start lg:justify-between">
                  <div className="min-w-0 space-y-1.5">
                    <div className="flex flex-wrap items-center gap-2">
                      <ShieldQuestion size={16} className="text-warning" aria-hidden />
                      <span className="font-medium">{v.app.displayName}</span>
                      <span className="font-mono text-xs">{v.version}</span>
                      <Badge tone="warn">{why.label}</Badge>
                    </div>
                    <p className="text-sm text-muted">{why.text}</p>
                    <dl className="grid grid-cols-[max-content_1fr] gap-x-3 gap-y-0.5 text-xs">
                      <dt className="text-muted">Signed by</dt>
                      <dd className="font-medium">{v.signerOrg}</dd>
                      <dt className="text-muted">Pinned now</dt>
                      <dd>{v.app.expectedPublisher ?? "nothing yet"}</dd>
                      <dt className="text-muted">File version</dt>
                      <dd className="font-mono">{v.fileVersion ?? "unreadable"}{v.fileVersion && v.fileVersion !== v.version ? ` (catalog says ${v.version})` : ""}</dd>
                      <dt className="text-muted">SHA-256</dt>
                      <dd className="break-all font-mono">{v.sha256}</dd>
                      {v.catalogSha256 && v.catalogSha256 !== v.sha256 && (
                        <>
                          <dt className="text-muted">Catalog hash</dt>
                          <dd className="break-all font-mono text-danger">{v.catalogSha256}</dd>
                        </>
                      )}
                      <dt className="text-muted">Downloaded from</dt>
                      <dd className="break-all">{hostOf(v.installerUrl)}</dd>
                      <dt className="text-muted">Held since</dt>
                      <dd>{fmtDate(v.createdAt)}</dd>
                    </dl>
                  </div>
                  {isAdmin && (
                    <div className="flex shrink-0 gap-2">
                      <ActionButton
                        url={`/api/packages/${v.id}/approve`}
                        label="Approve"
                        variant="primary"
                        icon={<CheckCircle2 size={15} />}
                        confirmText={`Trust ${v.app.displayName} ${v.version} signed by "${v.signerOrg}" (sha256 ${v.sha256})?${v.holdReason === "HASH_DRIFT" ? "" : " Future versions from this signer will be accepted automatically."}`}
                      />
                      <ActionButton url={`/api/packages/${v.id}/reject`} label="Reject" variant="danger" icon={<XCircle size={15} />} confirmText="Reject and delete this download?" />
                    </div>
                  )}
                </li>
              );
            })}
          </ul>
        </Card>
      )}

      <Card title="Third-party allow-list" description="Only these apps are fetched. Each download must match the catalog SHA-256 and a pinned signer; anything new or different is held for a decision. Each bank patches only the apps it has enabled." padded={apps.length === 0}>
        {apps.length === 0 ? (
          <EmptyState title="No apps on the allow-list yet" />
        ) : (
          <table className={tableCls}>
            <thead className={theadCls}>
              <tr><th>App</th><th>Publisher pin</th><th>Allowed hosts</th><th>Recent versions</th><th>{tenant ? tenant.name : "Bank"}</th></tr>
            </thead>
            <tbody>
              {apps.map((a) => (
                <tr key={a.id} className={rowCls}>
                  <td>
                    <div className="font-medium">{a.displayName}</div>
                    <div className="font-mono text-xs text-muted">{a.wingetId}</div>
                  </td>
                  <td className="text-xs">{a.expectedPublisher ?? <span className="text-warning">learned on first download (held)</span>}</td>
                  <td className="max-w-xs space-y-1 text-xs text-muted">
                    <div>{a.allowedDomains.length > 0 ? a.allowedDomains.join(", ") : "vendor host from the winget manifest"}</div>
                    <div className="flex flex-wrap gap-1">
                      <Badge tone={a.strictHosts ? "info" : "neutral"} dot={false}>{a.strictHosts ? "strict hosts" : "mirrors allowed"}</Badge>
                      {a.allowHashDrift && <Badge tone="warn" dot={false}>rolling URL</Badge>}
                    </div>
                  </td>
                  <td className="space-y-1.5">
                    {a.versions.length === 0 && <span className="text-xs text-muted">not fetched yet</span>}
                    {a.versions.map((v) => {
                      const quarantined = v.verification === "VERIFIED" && v.availableAt && v.availableAt > now;
                      return (
                        <div key={v.id} className="flex flex-wrap items-center gap-2 text-xs">
                          <span className="font-mono">{v.version}</span>
                          <span className="rounded bg-neutral-soft px-1.5 py-0.5 text-[10px] uppercase text-muted">{v.installerKind.toLowerCase()}</span>
                          {quarantined ? (
                            <Badge tone="warn">{`quarantine until ${fmtDate(v.availableAt)}`}</Badge>
                          ) : (
                            <Badge>{v.verification}</Badge>
                          )}
                          {v.rejectReason && <div className="w-full text-danger">{v.rejectReason}</div>}
                        </div>
                      );
                    })}
                  </td>
                  <td className="whitespace-nowrap">
                    {enabled === null ? (
                      <span className="text-xs text-muted">select a bank</span>
                    ) : (
                      <div className="flex flex-col items-start gap-1.5">
                        {enabled.has(a.id) ? <Badge tone="good">enabled</Badge> : <Badge tone="neutral">not enabled</Badge>}
                        {canToggleBank &&
                          (enabled.has(a.id) ? (
                            <ActionButton
                              url={`/api/apps/${a.id}/disable`}
                              label="Disable"
                              icon={<MinusCircle size={15} />}
                              confirmText={`Stop patching ${a.displayName} for ${tenant?.name}? Open change requests with it will no longer deploy.`}
                            />
                          ) : (
                            <ActionButton
                              url={`/api/apps/${a.id}/enable`}
                              label="Enable for this bank"
                              variant="primary"
                              icon={<PlusCircle size={15} />}
                              confirmText={`Patch ${a.displayName} on ${tenant?.name}'s PCs?`}
                            />
                          ))}
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>

      {isAdmin && (
        <Card title="Add app" description="PatchGate admins only: adds to the shared allow-list (banks then enable it). Every change is audited.">
          <AddAppForm />
        </Card>
      )}

      <Card
        title="Tactical RMM release mirror"
        description="The offline Tactical server and agents update only from these files. Unsigned agent builds whose SHA-256 matches GitHub's digest wait here for admin approval."
        padded={mirrors.length === 0}
      >
        {mirrors.length === 0 ? (
          <EmptyState title="Nothing mirrored yet">The fetch worker runs hourly.</EmptyState>
        ) : (
          <table className={tableCls}>
            <thead className={theadCls}>
              <tr><th>Component</th><th>Version</th><th>File</th><th>SHA-256</th><th>Status</th><th /></tr>
            </thead>
            <tbody>
              {mirrors.map((m) => (
                <tr key={m.id} className={rowCls}>
                  <td className="whitespace-nowrap">{m.component === "TACTICAL_AGENT" ? "Agent" : "Server"}</td>
                  <td className="font-mono text-xs">{m.version}</td>
                  <td className="text-xs">{m.assetName}</td>
                  <td className="font-mono text-xs text-muted" title={m.sha256}>{m.sha256.slice(0, 16)}…</td>
                  <td>
                    <Badge>{m.verification}</Badge>
                    {m.rejectReason && <div className="mt-1 max-w-xs text-xs text-muted">{m.rejectReason}</div>}
                  </td>
                  <td>
                    {isAdmin && m.verification === "PENDING" && (
                      <div className="flex gap-2">
                        <ActionButton url={`/api/mirror/${m.id}/approve`} label="Approve" variant="primary" icon={<CheckCircle2 size={15} />} confirmText={`Approve ${m.assetName} (sha256 ${m.sha256})?`} />
                        <ActionButton url={`/api/mirror/${m.id}/reject`} label="Reject" variant="danger" icon={<XCircle size={15} />} confirmText="Reject and delete this file?" />
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>

      {platformStaff && (
      <Card title="Recent fetch runs" description="The only component that reaches the internet." padded={runs.length === 0}>
        {runs.length === 0 ? (
          <EmptyState title="No fetch runs yet" />
        ) : (
          <table className={tableCls}>
            <thead className={theadCls}>
              <tr><th>Source</th><th>Started</th><th>Result</th></tr>
            </thead>
            <tbody>
              {runs.map((r) => (
                <tr key={r.id} className={rowCls}>
                  <td className="font-mono text-xs">{r.source}</td>
                  <td className="whitespace-nowrap text-xs text-muted">{fmtDate(r.startedAt)}</td>
                  <td className="text-xs">
                    <div className="flex flex-wrap items-center gap-2">
                      {r.ok === null ? <Badge tone="busy">running</Badge> : r.ok ? <Badge tone="good">ok</Badge> : <Badge tone="bad">failed</Badge>}
                      <span className="text-muted">{r.message}</span>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
      )}
    </div>
  );
}

const HOLD_TEXT = {
  FIRST_SIGNER: { label: "first signer", text: "First download for this app. Check that the signer is the real vendor before trusting it." },
  SIGNER_CHANGED: { label: "signer changed", text: "Validly signed, but by an organisation that is not pinned. Vendors rename (e.g. after acquisitions) — but so do impostors." },
  HASH_DRIFT: { label: "hash drift", text: "Signed by the pinned vendor, but the bytes differ from the catalog (the vendor URL serves a newer build). Approving trusts this exact file only." },
} as const;

function hostOf(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}

export default function AppsPage() {
  return (
    <div>
      <PageHeader title="Apps & mirror" description="Third-party packages and Tactical RMM releases that PatchGate fetches, verifies and serves to the offline zone." />
      <Suspense fallback={<Loading />}>
        <AppsContent />
      </Suspense>
    </div>
  );
}
