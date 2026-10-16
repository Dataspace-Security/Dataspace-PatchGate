import { CheckCheck } from "lucide-react";
import type { TacticalActivityList } from "@/lib/connector/tactical-activity";
import { describeActivity } from "@/lib/connector/tactical-activity-rules";
import { ActionButton } from "@/components/action-button";
import { Alert, Badge, Card, fmtDate, rowCls, tableCls, theadCls } from "@/components/ui";

/**
 * "Tactical activity": what happened in a site's Tactical outside PatchGate (Tactical seal, RUNBOOK
 * "Tactical is sealed"). ADMIN and AUDITOR read it; ADMIN acknowledges (per bank, audited).
 */

const SOURCE_LABEL: Readonly<Record<string, string>> = {
  AUDIT_LOG: "Tactical audit log",
  APPROVAL_GUARD: "approval guard (real time)",
  APPROVAL_DRIFT: "approval check",
  AUDIT_RESET: "audit log gap",
};

export function TacticalActivityCard({ list, canAck, showBank }: { list: TacticalActivityList; canAck: boolean; showBank: boolean }) {
  const openBanks = [...new Map(list.rows.filter((r) => !r.acknowledgedAt).map((r) => [r.tenantId, r.tenantName])).entries()];
  return (
    <Card
      title="Tactical activity"
      description="Actions in a site's Tactical RMM that PatchGate did not make: dashboard logins (also break-glass), scripts, commands, approvals, policy or user changes. Nobody should patch through Tactical directly."
      actions={list.unacknowledged > 0 ? <Badge tone="bad">{`${list.unacknowledged} unacknowledged`}</Badge> : <Badge tone="good">nothing open</Badge>}
      padded={false}
    >
      {list.unacknowledged > 0 && (
        <div className="space-y-2 p-4">
          <Alert tone="bad">
            {list.unacknowledged} action(s) in Tactical outside PatchGate. Find out who did it and why (RUNBOOK “Tactical is sealed”), then acknowledge.
          </Alert>
          {canAck && (
            <div className="flex flex-wrap gap-2">
              {openBanks.map(([tenantId, name]) => (
                <ActionButton
                  key={tenantId}
                  url="/api/tactical-activity/ack"
                  body={{ tenantId }}
                  askReason
                  label={showBank ? `Acknowledge all — ${name}` : "Acknowledge all"}
                  icon={<CheckCheck size={14} aria-hidden />}
                />
              ))}
            </div>
          )}
        </div>
      )}
      {list.rows.length === 0 ? (
        <p className="p-4 text-sm text-muted">No out-of-band Tactical activity recorded.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className={tableCls}>
            <thead className={theadCls}>
              <tr>
                <th>When</th>
                {showBank && <th>Bank</th>}
                <th>Site</th>
                <th>What</th>
                <th>Source</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {list.rows.map((r) => (
                <tr key={r.id} className={`${rowCls} align-top`}>
                  <td className="whitespace-nowrap text-xs text-muted">{fmtDate(r.occurredAt)}</td>
                  {showBank && <td className="text-xs">{r.tenantName}</td>}
                  <td className="text-xs">{r.connectorName}</td>
                  <td className="max-w-xl text-xs">
                    <div className="text-fg">{describeActivity(r)}</div>
                    {r.ip && <div className="font-mono text-[11px] text-muted">from {r.ip}</div>}
                  </td>
                  <td className="whitespace-nowrap text-xs text-muted">{SOURCE_LABEL[r.source] ?? r.source}</td>
                  <td className="whitespace-nowrap text-xs">
                    {r.acknowledgedAt ? (
                      <span className="text-muted" title={`by ${r.acknowledgedBy ?? "?"}`}>
                        acknowledged {fmtDate(r.acknowledgedAt)}
                      </span>
                    ) : (
                      <Badge tone="bad">open</Badge>
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
