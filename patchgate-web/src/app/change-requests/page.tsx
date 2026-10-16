import Link from "next/link";
import { Suspense } from "react";
import { Plus } from "lucide-react";
import { withTenant } from "@/lib/tenancy";
import { getPageTenant } from "@/lib/tenancy/page";
import { EmergencyBadge } from "./emergency-badge";
import { BUTTON, Badge, EmptyState, Loading, PageHeader, buttonBase, fmtDate, rowCls, tableCls, tableWrapCls, theadCls } from "@/components/ui";

async function ChangeRequestTable() {
  const { tenant } = await getPageTenant(); // per-request + auth gate + active bank
  const items = await withTenant(tenant.id, (tx) =>
    tx.changeRequest.findMany({
      where: { tenantId: tenant.id },
      orderBy: { createdAt: "desc" },
      take: 100,
      include: {
        ring: { select: { name: true } },
        createdBy: { select: { name: true } },
        approvedBy: { select: { name: true } },
        _count: { select: { patches: true } },
      },
    }),
  );

  if (items.length === 0) {
    return <EmptyState title="No change requests yet">Start from the Patches page: select patches and create a draft.</EmptyState>;
  }
  return (
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
              <td className="whitespace-nowrap">{cr.approvedBy?.name ?? <span className="text-muted">—</span>}</td>
              <td className="whitespace-nowrap text-xs text-muted">{fmtDate(cr.createdAt)}</td>
              <td>
                <Badge>{cr.status}</Badge>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function ChangeRequestsPage() {
  return (
    <div>
      <PageHeader
        title="Change requests"
        description="Every deployment needs a maker and a different checker. All decisions are written to the tamper-evident audit log."
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
