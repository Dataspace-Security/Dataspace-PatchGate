import Link from "next/link";
import { notFound } from "next/navigation";
import { Suspense } from "react";
import { ArrowLeft, Ban, CheckCircle2, Circle, Loader2, Rocket, Send, XCircle } from "lucide-react";
import { withTenant } from "@/lib/tenancy";
import { getPageTenant } from "@/lib/tenancy/page";
import { requiredApprovalsOf, transition, type CrAction } from "@/lib/approvals/state-machine";
import { REBOOT_LABEL } from "@/lib/policies/reboot-labels";
import { ActionButton } from "@/components/action-button";
import { canWrite } from "@/lib/auth/roles";
import { Alert, Badge, Card, EmptyState, Loading, fmtDate, rowCls, tableCls, theadCls } from "@/components/ui";
import { EmergencyBadge } from "../emergency-badge";
import { DraftOptions } from "./draft-options";

const ACTIONS: {
  action: CrAction;
  label: string;
  variant: "primary" | "danger" | "default";
  icon: React.ReactNode;
  confirm?: string;
  reason?: boolean;
  body?: { deployNow: true };
}[] = [
  { action: "submit", label: "Submit for approval", variant: "primary", icon: <Send size={15} /> },
  { action: "approve", label: "Approve", variant: "primary", icon: <CheckCircle2 size={15} />, confirm: "Approve this change request? This is recorded in the audit log." },
  { action: "reject", label: "Reject", variant: "danger", icon: <XCircle size={15} />, reason: true },
  { action: "deploy", label: "Queue deployment", variant: "primary", icon: <Rocket size={15} />, confirm: "Queue deployment to every endpoint in the ring?" },
  { action: "cancel", label: "Cancel", variant: "default", icon: <Ban size={15} />, confirm: "Cancel this change request?" },
];

const KIND_LABEL = { WINDOWS: "Windows", THIRD_PARTY: "Third-party", AGENT_UPGRADE: "Tactical agent" } as const;

function Step({ done, active = false, title, who, when }: { done: boolean; active?: boolean; title: string; who?: string | null; when?: Date | null }) {
  return (
    <li className="flex min-w-0 flex-1 items-start gap-3">
      {done ? (
        <CheckCircle2 size={20} className="mt-0.5 shrink-0 text-success" />
      ) : active ? (
        <Loader2 size={20} className="mt-0.5 shrink-0 animate-spin text-busy" />
      ) : (
        <Circle size={20} className="mt-0.5 shrink-0 text-border-strong" />
      )}
      <div className="min-w-0">
        <div className={`text-sm font-medium ${done ? "text-fg" : "text-muted"}`}>{title}</div>
        <div className="truncate text-xs text-muted">{who ?? "—"}</div>
        <div className="text-xs text-muted">{fmtDate(when)}</div>
      </div>
    </li>
  );
}

async function Detail({ params }: { params: Promise<{ id: string }> }) {
  const { user, tenant } = await getPageTenant();
  const { id } = await params;
  const tenantId = tenant.id;
  // Another bank's request is simply not found (filter + RLS).
  const data = await withTenant(tenantId, async (tx) => {
    const cr = await tx.changeRequest.findFirst({
      where: { id, tenantId },
      include: {
        ring: true,
        window: true,
        createdBy: { select: { name: true, upn: true } },
        approvedBy: { select: { name: true, upn: true } },
        approvals: { orderBy: { createdAt: "asc" } },
        patches: { include: { patch: true } },
        deployments: { include: { endpoint: { select: { hostname: true, site: true } } }, orderBy: { status: "asc" } },
      },
    });
    if (!cr) return null;
    const audit = await tx.auditEvent.findMany({
      where: {
        tenantId,
        OR: [
          { entity: "ChangeRequest", entityId: id },
          { entity: "Deployment", entityId: { in: cr.deployments.map((d) => d.id) } },
        ],
      },
      orderBy: { seq: "asc" },
      take: 200,
    });
    return { cr, audit };
  });
  if (!data) notFound();
  const { cr, audit } = data;

  const snapshot = {
    status: cr.status,
    createdById: cr.createdById,
    patchCount: cr.patches.length,
    tenantId: cr.tenantId,
    requireBankApproval: tenant.requireBankApproval,
    emergency: cr.emergency,
    emergencyReason: cr.emergencyReason,
    requiredApprovals: cr.requiredApprovals,
    approvalExpiresAt: cr.approvalExpiresAt,
    approvals: cr.status === "PENDING_APPROVAL" || cr.status === "APPROVED" ? cr.approvals : [],
  };
  const required = requiredApprovalsOf(snapshot);
  const round = snapshot.approvals;
  const now = new Date();
  const expired = cr.status === "APPROVED" && cr.approvalExpiresAt !== null && cr.approvalExpiresAt <= now;
  // The approval covers the endpoints snapshotted at submission; say how many in the confirmation.
  const targetsText = cr.targetCount === null ? "" : ` (${cr.targetCount} endpoint${cr.targetCount === 1 ? "" : "s"}, fixed when it was submitted)`;
  const allowed = ACTIONS.filter((a) => transition(snapshot, a.action, user, { now }).ok).flatMap((a) =>
    a.action === "approve"
      ? [
          {
            ...a,
            label: required > 1 ? `Approve (${round.length + 1} of ${required})` : a.label,
            confirm: `Approve this change request${targetsText}? This is recorded in the audit log.`,
          },
          ...(cr.emergency
            ? [
                {
                  ...a,
                  label: "Approve & deploy now",
                  variant: "danger" as const,
                  body: { deployNow: true as const },
                  confirm: `EMERGENCY: approve AND confirm deploying immediately, outside the maintenance window${targetsText}? The window is bypassed only if both approvers confirm.`,
                },
              ]
            : []),
        ]
      : a.action === "deploy"
        ? [{ ...a, confirm: `Queue deployment to the approved endpoints${targetsText}?` }]
        : [a],
  );
  const canEditDraft = cr.status === "DRAFT" && cr.createdById === user.id && canWrite(user);
  const counts = cr.deployments.reduce<Record<string, number>>((acc, d) => ({ ...acc, [d.status]: (acc[d.status] ?? 0) + 1 }), {});
  const deploying = cr.status === "DEPLOYING";
  const deployed = ["COMPLETED", "PARTIAL", "FAILED"].includes(cr.status);

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4 border-b border-border pb-5">
        <div>
          <h1 className="flex flex-wrap items-center gap-3 text-2xl font-semibold tracking-tight text-fg">
            {cr.title} {cr.emergency && <EmergencyBadge />}
          </h1>
          <p className="mt-1 text-sm text-muted">
            Ring <b className="text-fg">{cr.ring.name}</b> · Window <b className="text-fg">{cr.window?.name ?? "none (immediate)"}</b> · Ticket{" "}
            <b className="font-mono text-fg">{cr.ticketRef ?? "—"}</b> · Target endpoints{" "}
            <b className="text-fg">{cr.targetCount === null ? "fixed on submit" : cr.targetCount}</b> · Reboot{" "}
            <b className="text-fg">{cr.rebootPolicy ? REBOOT_LABEL[cr.rebootPolicy] : cr.window ? REBOOT_LABEL[cr.window.rebootPolicy] : REBOOT_LABEL.REQUIRED}</b>
          </p>
          {cr.emergency && (
            <p className="mt-2 max-w-3xl text-sm text-danger">
              <b>Emergency reason:</b> {cr.emergencyReason}
            </p>
          )}
        </div>
        <Badge>{cr.status}</Badge>
      </div>

      <Card
        title="Approval"
        description={`Maker and checker must be different people (enforced server-side).${tenant.requireBankApproval ? ` The checker must be an admin of ${tenant.name}.` : ""} The request deploys only to the endpoints in its ring when it was submitted; changing the targets needs a new request and approval.`}
      >
        <ol className="flex flex-col gap-4 sm:flex-row sm:gap-6">
          <Step done title="Created (maker)" who={cr.createdBy.name} when={cr.createdAt} />
          <Step done={cr.submittedAt !== null} title="Submitted" who={cr.createdBy.name} when={cr.submittedAt} />
          <Step
            done={cr.approvedById !== null}
            title={required > 1 ? `Approved (${Math.min(round.length, required)} of ${required} checkers)` : "Approved (checker)"}
            who={round.length > 0 ? round.map((a) => a.userName).join(", ") : cr.approvedBy?.name}
            when={cr.decidedAt}
          />
          <Step
            done={deployed}
            active={deploying}
            title={deploying ? "Deploying…" : deployed ? `Deployment ${cr.status.toLowerCase()}` : "Deployment"}
            who={deploying || deployed ? cr.ring.name : null}
            when={cr.completedAt}
          />
        </ol>
        {required > 1 && cr.status === "PENDING_APPROVAL" && (
          <div className="mt-4">
            <Alert tone="warn">
              Needs {required} different approvers (never the maker){tenant.requireBankApproval ? `, at least one from ${tenant.name}` : ""}. {round.length} so far
              {round.length > 0 ? `: ${round.map((a) => `${a.userName}${a.deployNow ? " (deploy now)" : ""}`).join(", ")}` : ""}.
            </Alert>
          </div>
        )}
        {cr.windowBypass && (
          <div className="mt-4">
            <Alert tone="bad">Maintenance window bypassed: both approvers confirmed “deploy now”. This request deploys as soon as it is queued.</Alert>
          </div>
        )}
        {cr.status === "APPROVED" && cr.approvalExpiresAt && (
          <div className="mt-4">
            <Alert tone={expired ? "bad" : "info"}>
              {expired ? "Approval expired" : "Approval valid until"} {fmtDate(cr.approvalExpiresAt)}
              {expired ? " — cancel this request and raise a new one." : " (bank policy)."}
            </Alert>
          </div>
        )}
        {cr.rejectReason && (
          <div className="mt-4">
            <Alert tone="bad">Rejected: {cr.rejectReason}</Alert>
          </div>
        )}
        <div className="mt-5 flex flex-wrap gap-2 border-t border-border pt-4">
          {allowed.length === 0 && <span className="text-sm text-muted">No actions available for you at this stage.</span>}
          {allowed.map((a) => (
            <ActionButton
              key={`${a.action}${a.body ? "-now" : ""}`}
              body={a.body}
              url={`/api/change-requests/${cr.id}/${a.action}`}
              label={a.label}
              variant={a.variant}
              icon={a.icon}
              confirmText={a.confirm}
              askReason={a.reason}
            />
          ))}
        </div>
      </Card>

      {canEditDraft && (
        <details className="group rounded-xl border border-border bg-surface shadow-card" data-testid="cr-advanced-options">
          <summary className="cursor-pointer select-none px-5 py-4 text-sm font-semibold text-fg">
            Advanced options <span className="font-normal text-muted">— reboot policy, emergency change (optional; the defaults suit most requests)</span>
          </summary>
          <div className="border-t border-border px-5 py-4">
            <p className="mb-4 text-xs text-muted">Only you (the maker) can change these, and only before submitting.</p>
            <DraftOptions crId={cr.id} emergency={cr.emergency} emergencyReason={cr.emergencyReason} rebootPolicy={cr.rebootPolicy ?? cr.window?.rebootPolicy ?? "REQUIRED"} />
          </div>
        </details>
      )}

      <Card title={`Patches (${cr.patches.length})`} padded={false}>
        <table className={tableCls}>
          <thead className={theadCls}>
            <tr><th>Title</th><th>KB</th><th>Type</th><th>Severity</th></tr>
          </thead>
          <tbody>
            {cr.patches.map(({ patch: p }) => (
              <tr key={p.id} className={rowCls}>
                <td className="font-medium">{p.title}</td>
                <td className="font-mono text-xs text-muted">{p.kb ?? "—"}</td>
                <td className="whitespace-nowrap text-muted">{KIND_LABEL[p.kind]}</td>
                <td><Badge>{p.severity}</Badge></td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>

      <Card
        title={`Deployments (${cr.deployments.length})`}
        actions={
          <div className="flex flex-wrap gap-1.5">
            {Object.entries(counts).map(([s, n]) => (
              <Badge key={s} tone={s === "SUCCEEDED" ? "good" : s === "FAILED" || s === "TIMED_OUT" ? "bad" : "neutral"}>{`${s.replace("_", " ").toLowerCase()} ${n}`}</Badge>
            ))}
          </div>
        }
        padded={cr.deployments.length === 0}
      >
        {cr.deployments.length === 0 ? (
          <EmptyState title="Not deployed yet">Deployments appear here once an approved request is queued.</EmptyState>
        ) : (
          <table className={tableCls}>
            <thead className={theadCls}>
              <tr><th>Endpoint</th><th>Branch</th><th>Status</th><th className="text-right">Attempts</th><th>Note / error</th><th>Finished</th></tr>
            </thead>
            <tbody>
              {cr.deployments.map((d) => (
                <tr key={d.id} className={rowCls}>
                  <td className="whitespace-nowrap font-medium">{d.endpoint.hostname}</td>
                  <td className="whitespace-nowrap text-muted">{d.endpoint.site ?? "—"}</td>
                  <td><Badge>{d.status}</Badge></td>
                  <td className="text-right tabular-nums">{d.attempts}</td>
                  <td className={`max-w-md text-xs ${d.error ? "text-danger" : "text-muted"}`}>{d.error ?? d.note ?? ""}</td>
                  <td className="whitespace-nowrap text-xs text-muted">{fmtDate(d.finishedAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>

      <Card title="Audit trail" description="Hash-chained and streamed to the bank SIEM.">
        <ol className="relative space-y-3 border-l border-border pl-5">
          {audit.map((a) => (
            <li key={a.seq.toString()} className="relative">
              <span aria-hidden className="absolute -left-[25px] top-1.5 h-2.5 w-2.5 rounded-full border-2 border-surface bg-primary" />
              <div className="text-sm">
                <span className="font-medium text-fg">{a.action.replace(/[._]/g, " ")}</span> <span className="text-muted">by {a.actor}</span>
              </div>
              <div className="font-mono text-xs text-muted">#{a.seq.toString()} · {fmtDate(a.ts)}</div>
            </li>
          ))}
        </ol>
      </Card>
    </div>
  );
}

export default function ChangeRequestPage(props: PageProps<"/change-requests/[id]">) {
  return (
    <div className="space-y-4">
      <Link href="/change-requests" className="inline-flex items-center gap-1.5 text-sm text-muted hover:text-primary">
        <ArrowLeft size={15} /> All change requests
      </Link>
      <Suspense fallback={<Loading />}>
        <Detail params={props.params} />
      </Suspense>
    </div>
  );
}
