import Link from "next/link";
import { Suspense } from "react";
import { Plus } from "lucide-react";
import { withTenant } from "@/lib/tenancy";
import { getPageTenant } from "@/lib/tenancy/page";
import { ApprovalOffNote } from "@/components/approval-off-note";
import { DeploymentProgress } from "@/components/deployment-progress";
import { LiveRefresh } from "@/components/live-refresh";
import { progressFromCounts } from "@/lib/deploy/progress";
import { EmergencyBadge } from "./emergency-badge";
import { BUTTON, Badge, EmptyState, Loading, PageHeader, buttonBase, fmtDate, rowCls, tableCls, tableWrapCls, theadCls } from "@/components/ui";

async function ChangeRequestTable() {
  const { tenant } = await getPageTenant(); // per-request + auth gate + active bank
  const { items, counts } = await withTenant(tenant.id, async (tx) => {
    const items = await tx.changeRequest.findMany({
      where: { tenantId: tenant.id },
      orderBy: { createdAt: "desc" },
      take: 100,
      include: {
        ring: { select: { name: true } },
        createdBy: { select: { name: true } },
        approvedBy: { select: { name: true } },
        _count: { select: { patches: true } },
      },
    });
    // Rollout progress of the listed requests that have deployments (one grouped query).
    const rolled = items.filter((cr) => ["DEPLOYING", "COMPLETED", "PARTIAL", "FAILED"].includes(cr.status)).map((cr) => cr.id);
    const groups =
      rolled.length > 0
        ? await tx.deployment.groupBy({ by: ["changeRequestId", "status"], where: { tenantId: tenant.id, changeRequestId: { in: rolled } }, _count: { _all: true } })
        : [];
    const counts = new Map<string, Record<string, number>>();
    for (const g of groups) counts.set(g.changeRequestId, { ...(counts.get(g.changeRequestId) ?? {}), [g.status]: g._count._all });
    return { items, counts };
  });
  const live = (
    <div className="flex justify-end">
      <LiveRefresh active={items.some((cr) => cr.status === "DEPLOYING")} />
    </div>
  );

  if (items.length === 0) {
    return (
      <div className="space-y-4">
        {live}
        <ApprovalOffNote approvalRequired={tenant.requireBankApproval} />
        <EmptyState title="No change requests yet">Start from the Patches page: select patches and create a draft.</EmptyState>
      </div>
    );
  }
  return (
    <div className="space-y-4">
      {live}
      <ApprovalOffNote approvalRequired={tenant.requireBankApproval} />
      <div className={tableWrapCls}>
        <table className={tableCls}>
          <thead className={theadCls}>
            <tr>
              <th>Title</th>
              <th>Ticket</th>
              <th>Ring</th>
              <th className="text-right">Patches</th>
              <th>Maker</th>
              <th>Checker</th>
              <th>Created</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {items.map((cr) => (
              <tr key={cr.id} className={rowCls}>
                <td>
                  <span className="flex flex-wrap items-center gap-2">
                    <Link href={`/change-requests/${cr.id}`} className="font-medium text-primary hover:underline">
                      {cr.title}
                    </Link>
                    {cr.emergency && <EmergencyBadge />}
                  </span>
                </td>
                <td className="font-mono text-xs text-muted">{cr.ticketRef ?? "—"}</td>
                <td className="whitespace-nowrap">{cr.ring.name}</td>
                <td className="text-right tabular-nums">{cr._count.patches}</td>
                <td className="whitespace-nowrap">{cr.createdBy.name}</td>
                <td className="whitespace-nowrap">
                  {cr.approvedBy?.name ?? (cr.autoApproved ? <span className="text-warning">auto (approval off)</span> : <span className="text-muted">—</span>)}
                </td>
                <td className="whitespace-nowrap text-xs text-muted">{fmtDate(cr.createdAt)}</td>
                <td>
                  <Badge>{cr.status}</Badge>
                  {counts.has(cr.id) && (
                    <div className="mt-1.5">
                      <DeploymentProgress progress={progressFromCounts(counts.get(cr.id) ?? {})} compact />
                    </div>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default function ChangeRequestsPage() {
  return (
    <div>
      <PageHeader
        title="Change requests"
        description="Each request has a maker and — while approval is on — a different checker. All decisions are written to the tamper-evident audit log."
        actions={
          <Link href="/patches" className={`${buttonBase} ${BUTTON.primary}`}>
            <Plus size={15} /> New change request
          </Link>
        }
      />
      <Suspense fallback={<Loading />}>
        <ChangeRequestTable />
      </Suspense>
    </div>
  );
}
