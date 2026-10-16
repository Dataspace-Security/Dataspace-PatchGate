"use client";

import { useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { AppWindow, Cpu, Loader2, Lock, MonitorCog, Send } from "lucide-react";
import { callApi } from "@/components/api-client";
import { BUTTON, Badge, EmptyState, buttonBase, inputCls, labelCls, rowCls, tableCls, tableWrapCls, theadCls } from "@/components/ui";

export interface PatchRow {
  id: string;
  title: string;
  kb: string | null;
  kind: "WINDOWS" | "THIRD_PARTY" | "AGENT_UPGRADE";
  severity: string;
  classification: string | null;
  needed: number;
  blockedReason: string | null;
}

export interface RingOption {
  id: string;
  name: string;
  windows: { id: string; name: string }[];
}

interface Props {
  patches: PatchRow[];
  rings: RingOption[];
  canCreate: boolean;
}

const KIND = {
  WINDOWS: { label: "Windows", Icon: MonitorCog },
  THIRD_PARTY: { label: "Third-party", Icon: AppWindow },
  AGENT_UPGRADE: { label: "Tactical agent", Icon: Cpu },
} as const;

export function PatchPicker({ patches, rings, canCreate }: Props) {
  const router = useRouter();
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [title, setTitle] = useState("");
  const [ticketRef, setTicketRef] = useState("");
  const [ringId, setRingId] = useState(rings[0]?.id ?? "");
  // "" = use the ring/bank default (Settings → Approvals / Rings)
  const [rebootPolicy, setRebootPolicy] = useState<"" | "NEVER" | "REQUIRED" | "ALWAYS">("");
  const [emergency, setEmergency] = useState(false);
  const [emergencyReason, setEmergencyReason] = useState("");
  const [windowId, setWindowId] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const windows = useMemo(() => rings.find((r) => r.id === ringId)?.windows ?? [], [rings, ringId]);

  function toggle(id: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    const r = await callApi<{ id: string }>("/api/change-requests", "POST", {
      title,
      ticketRef: ticketRef || undefined,
      ringId,
      windowId: windowId || undefined,
      patchIds: [...selected],
    });
    if (!r.ok) {
      setBusy(false);
      return setError(r.error);
    }
    // Emergency flag / reboot policy are draft options (own endpoint: audited, two approvers for emergencies).
    if (emergency || rebootPolicy) {
      const o = await callApi(`/api/change-requests/${r.data.id}/options`, "PATCH", {
        ...(rebootPolicy ? { rebootPolicy } : {}),
        ...(emergency ? { emergency: true, emergencyReason } : {}),
      });
      if (!o.ok) {
        setBusy(false);
        return setError(`Draft created, but its options were not saved: ${o.error}. Open the draft to set them.`);
      }
    }
    setBusy(false);
    router.push(`/change-requests/${r.data.id}`);
  }

  return (
    <div className="grid gap-6 xl:grid-cols-[1fr_340px]">
      {patches.length === 0 ? (
        <EmptyState title="No patches match this filter">Try “All (incl. not needed)”, or run a scan from Endpoints.</EmptyState>
      ) : (
        <div className={tableWrapCls}>
          <table className={tableCls}>
            <thead className={theadCls}>
              <tr>
                <th className="w-10" aria-label="Select" />
                <th>Patch</th>
                <th>Type</th>
                <th>Severity</th>
                <th className="text-right">PCs needing</th>
              </tr>
            </thead>
            <tbody>
              {patches.map((p) => {
                const { label, Icon } = KIND[p.kind];
                const disabled = !canCreate || p.blockedReason !== null;
                const checked = selected.has(p.id);
                return (
                  <tr key={p.id} className={`${rowCls} ${checked ? "bg-primary-soft/60" : ""}`}>
                    <td>
                      <input
                        type="checkbox"
                        aria-label={`Select ${p.title}`}
                        checked={checked}
                        disabled={disabled}
                        onChange={() => toggle(p.id)}
                        className="h-4 w-4 accent-[var(--primary)] disabled:opacity-40"
                      />
                    </td>
                    <td>
                      <div className="font-medium text-fg">{p.title}</div>
                      <div className="mt-0.5 flex flex-wrap items-center gap-x-2 text-xs text-muted">
                        {p.kb && <span className="font-mono">{p.kb}</span>}
                        {p.classification && <span>{p.classification}</span>}
                        {p.blockedReason && (
                          <span className="inline-flex items-center gap-1 text-warning">
                            <Lock size={12} /> {p.blockedReason}
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="whitespace-nowrap">
                      <span className="inline-flex items-center gap-1.5 text-muted">
                        <Icon size={15} /> {label}
                      </span>
                    </td>
                    <td>
                      <Badge>{p.severity}</Badge>
                    </td>
                    <td className="text-right tabular-nums">{p.needed}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      <form method="post" onSubmit={submit} className="h-fit space-y-4 rounded-xl border border-border bg-surface p-5 shadow-card xl:sticky xl:top-6">
        <div>
          <h2 className="font-semibold text-fg">New change request</h2>
          <p className="mt-0.5 text-xs text-muted">A second person (checker) must approve before anything deploys.</p>
        </div>
        {!canCreate && <p className="rounded-lg bg-warning-soft px-3 py-2 text-sm text-warning">Read-only (auditor): only admins create change requests.</p>}
        <div className="rounded-lg bg-surface-2 px-3 py-2 text-sm">
          <span className="font-semibold text-fg">{selected.size}</span> <span className="text-muted">patch(es) selected</span>
        </div>
        <label className={labelCls}>
          Title
          <input className={inputCls} value={title} onChange={(e) => setTitle(e.target.value)} required minLength={3} maxLength={200} placeholder="October Patch Tuesday — pilot" />
        </label>
        <label className={labelCls}>
          Change ticket <span className="font-normal text-muted">(optional)</span>
          <input className={inputCls} value={ticketRef} onChange={(e) => setTicketRef(e.target.value)} maxLength={64} placeholder="CHG-2026-1014" />
        </label>
        <label className={labelCls}>
          Target ring
          <select className={inputCls} value={ringId} onChange={(e) => { setRingId(e.target.value); setWindowId(""); }} required>
            {rings.map((r) => (
              <option key={r.id} value={r.id}>{r.name}</option>
            ))}
          </select>
        </label>
        <label className={labelCls}>
          Maintenance window
          <select className={inputCls} value={windowId} onChange={(e) => setWindowId(e.target.value)}>
            <option value="">None — deploy as soon as approved</option>
            {windows.map((w) => (
              <option key={w.id} value={w.id}>{w.name}</option>
            ))}
          </select>
        </label>
        <details className="rounded-lg border border-border px-3 py-2" data-testid="cr-form-advanced">
          <summary className="cursor-pointer select-none text-sm font-medium text-fg">
            Advanced options <span className="font-normal text-muted">(reboot, emergency)</span>
          </summary>
          <div className="mt-3 space-y-4">
        <label className={labelCls}>
          Reboot
          <select className={inputCls} value={rebootPolicy} onChange={(e) => setRebootPolicy(e.target.value as typeof rebootPolicy)}>
            <option value="">Ring / bank default</option>
            <option value="NEVER">Never reboot</option>
            <option value="REQUIRED">Reboot only if an update requires it</option>
            <option value="ALWAYS">Always reboot after installing</option>
          </select>
        </label>
        <label className="flex items-start gap-2 text-sm">
          <input type="checkbox" className="mt-0.5 size-4 accent-[var(--danger)]" checked={emergency} onChange={(e) => setEmergency(e.target.checked)} />
          <span>
            <span className="font-medium text-fg">Emergency change</span>
            <span className="block text-muted">Needs TWO different approvers; may bypass the maintenance window only if both confirm “deploy now”.</span>
          </span>
        </label>
        {emergency && (
          <label className={labelCls}>
            Emergency reason <span className="font-normal text-muted">(required, shown to approvers and auditors)</span>
            <textarea className={inputCls} value={emergencyReason} onChange={(e) => setEmergencyReason(e.target.value)} required minLength={10} maxLength={500} rows={3} placeholder="Actively exploited vulnerability CVE-…; bank CISO request …" />
          </label>
        )}
          </div>
        </details>
        {error && <p role="alert" className="rounded-lg bg-danger-soft px-3 py-2 text-sm text-danger">{error}</p>}
        <button type="submit" disabled={!canCreate || busy || selected.size === 0 || !ringId} className={`${buttonBase} ${BUTTON.primary} w-full`}>
          {busy ? <Loader2 size={15} className="animate-spin" /> : <Send size={15} />}
          {busy ? "Creating…" : "Create draft"}
        </button>
      </form>
    </div>
  );
}
