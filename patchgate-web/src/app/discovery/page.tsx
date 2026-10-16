import { Suspense } from "react";
import Link from "next/link";
import { EyeOff, Eye, ShieldPlus } from "lucide-react";
import { prisma } from "@/lib/db";
import { withTenant } from "@/lib/tenancy";
import { getPageTenant } from "@/lib/tenancy/page";
import { ActionButton } from "@/components/action-button";
import { Alert, Badge, Card, EmptyState, Loading, PageHeader, Stat, fmtDate, rowCls, tableCls, theadCls } from "@/components/ui";

const MATCH_LABEL = { PRODUCT_CODE: "MSI product code", NAME_PUBLISHER: "name + publisher", NONE: "no match" } as const;

async function DiscoveryContent({ showIgnored }: { showIgnored: boolean }) {
  const { user, tenant } = await getPageTenant();
  const tenantId = tenant.id;
  const isAdmin = user.role === "ADMIN";
  const platformAdmin = isAdmin && user.tenantId === null;

  const { products, endpoints } = await withTenant(tenantId, async (tx) => ({
    products: await tx.discoveredApp.findMany({
      where: { tenantId, ...(showIgnored ? {} : { ignored: false }) },
      orderBy: [{ endpointCount: "desc" }, { displayName: "asc" }],
      take: 500,
      include: { app: { select: { id: true, displayName: true } } },
    }),
    endpoints: await tx.endpoint.count({ where: { tenantId } }),
  }));
  // Shared (not bank data): the winget index is fetched once for everyone.
  const index = await prisma.fetchRun.findFirst({ where: { source: "winget-index" }, orderBy: { startedAt: "desc" } });
  // Which matched packages are already on the SHARED allow-list (bank admins can only opt in to those).
  const wingetIds = [...new Set(products.flatMap((p) => (p.wingetId && !p.appId ? [p.wingetId] : [])))];
  const listed = new Set((await prisma.app.findMany({ where: { wingetId: { in: wingetIds } }, select: { wingetId: true } })).map((a) => a.wingetId));
  const matched = products.filter((p) => p.wingetId).length;
  const managed = products.filter((p) => p.appId).length;
  const unmanagedMatched = products.filter((p) => p.wingetId && !p.appId && !p.ignored);

  return (
    <div className="space-y-6">
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Stat label="Products on PCs" value={products.length} hint={`across ${endpoints} endpoints`} />
        <Stat label="Matched to winget" value={matched} tone="good" />
        <Stat label="Managed by PatchGate" value={managed} tone="good" />
        <Stat label="Matched, not managed" value={unmanagedMatched.length} tone={unmanagedMatched.length > 0 ? "warn" : "neutral"} hint="patchable but unpatched" />
      </div>

      {!index?.ok && (
        <Alert tone="warn">
          The winget catalog index {index ? `could not be refreshed (${index.message ?? "unknown error"})` : "has not been downloaded yet"} — products are listed but not matched.
          It is fetched (Microsoft-signed) by the daily fetch loop.
        </Alert>
      )}

      <Card
        title="Installed software across the fleet"
        description={`From Tactical inventory, matched locally against the winget catalog${index?.ok ? ` (index ${fmtDate(index.startedAt)})` : ""}. Managing an app on the shared allow-list enables it for this bank. An app not on the list yet is requested from PatchGate: a platform administrator adds it (no signer pin; its first download is held until the signer is approved).`}
        actions={
          <Link href={showIgnored ? "/discovery" : "/discovery?ignored=1"} className="text-sm font-medium text-primary hover:underline">
            {showIgnored ? "Hide ignored" : "Show ignored"}
          </Link>
        }
        padded={products.length === 0}
      >
        {products.length === 0 ? (
          <EmptyState title="No inventory yet">Software appears here after the next scan ingestion.</EmptyState>
        ) : (
          <table className={tableCls}>
            <thead className={theadCls}>
              <tr><th>Product</th><th>PCs</th><th>Versions seen</th><th>winget package</th><th>Status</th><th /></tr>
            </thead>
            <tbody>
              {products.map((p) => (
                <tr key={p.id} className={`${rowCls} ${p.ignored ? "opacity-60" : ""}`}>
                  <td>
                    <div className="font-medium">{p.displayName}</div>
                    <div className="text-xs text-muted">{p.publisher ?? "unknown publisher"}</div>
                  </td>
                  <td className="tabular-nums">{p.endpointCount}</td>
                  <td className="max-w-[14rem] font-mono text-xs text-muted">{p.versions.slice(0, 4).join(", ")}{p.versions.length > 4 ? ` +${p.versions.length - 4}` : ""}</td>
                  <td>
                    {p.wingetId ? (
                      <>
                        <div className="font-mono text-xs">{p.wingetId}</div>
                        <div className="text-[11px] text-muted">via {MATCH_LABEL[p.match]}</div>
                      </>
                    ) : (
                      <span className="text-xs text-muted">—</span>
                    )}
                  </td>
                  <td>
                    {p.app ? (
                      <Badge tone="good">managed</Badge>
                    ) : p.requestedAt ? (
                      <Badge tone="info">requested</Badge>
                    ) : p.ignored ? (
                      <Badge tone="neutral">ignored</Badge>
                    ) : p.wingetId ? (
                      <Badge tone="warn">not managed</Badge>
                    ) : (
                      <Badge tone="neutral">unknown</Badge>
                    )}
                  </td>
                  <td>
                    {isAdmin && !p.app && (
                      <div className="flex justify-end gap-2">
                        {p.wingetId && !p.ignored && !p.requestedAt && (listed.has(p.wingetId) || platformAdmin) && (
                          <ActionButton
                            url={`/api/discovery/${p.id}/manage`}
                            label="Manage"
                            variant="primary"
                            icon={<ShieldPlus size={15} />}
                            confirmText={`Start patching ${p.displayName} via winget package ${p.wingetId} for this bank? A new package is held until its signer is approved.`}
                          />
                        )}
                        {p.wingetId && !p.ignored && !p.requestedAt && !listed.has(p.wingetId) && !platformAdmin && (
                          <ActionButton
                            url={`/api/discovery/${p.id}/manage`}
                            label="Request"
                            variant="primary"
                            icon={<ShieldPlus size={15} />}
                            confirmText={`${p.wingetId} is not on PatchGate's shared allow-list yet. Ask a PatchGate administrator to add it for this bank?`}
                          />
                        )}
                        {p.ignored ? (
                          <ActionButton url={`/api/discovery/${p.id}/unignore`} label="Unignore" icon={<Eye size={15} />} />
                        ) : (
                          <ActionButton url={`/api/discovery/${p.id}/ignore`} label="Ignore" icon={<EyeOff size={15} />} />
                        )}
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}

export default async function DiscoveryPage({ searchParams }: PageProps<"/discovery">) {
  return (
    <div>
      <PageHeader title="Discovery" description="What is actually installed on your PCs — and which of it PatchGate can keep patched." />
      <Suspense fallback={<Loading />}>
        <DiscoveryFromParams searchParams={searchParams} />
      </Suspense>
    </div>
  );
}

async function DiscoveryFromParams({ searchParams }: { searchParams: PageProps<"/discovery">["searchParams"] }) {
  const sp = await searchParams;
  return <DiscoveryContent showIgnored={sp.ignored === "1"} />;
}
