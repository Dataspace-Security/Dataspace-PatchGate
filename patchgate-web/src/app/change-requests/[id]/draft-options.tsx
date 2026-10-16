"use client";

import { useState, useTransition, type FormEvent } from "react";
import { useRouter } from "next/navigation";
import { Loader2 } from "lucide-react";
import { REBOOT_LABEL, REBOOT_POLICIES, type RebootPolicyValue } from "@/lib/policies/reboot-labels";
import { callApi } from "@/components/api-client";
import { Alert, BUTTON, buttonBase, inputCls, labelCls } from "@/components/ui";

interface Props {
  crId: string;
  emergency: boolean;
  emergencyReason: string | null;
  rebootPolicy: RebootPolicyValue;
}

/** Maker-only, DRAFT-only: mark the request as an emergency (reason required) and choose the reboot policy. */
export function DraftOptions({ crId, emergency, emergencyReason, rebootPolicy }: Props) {
  const router = useRouter();
  const [, start] = useTransition();
  const [d, setD] = useState({ emergency, emergencyReason: emergencyReason ?? "", rebootPolicy });
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ tone: "bad" | "good"; text: string } | null>(null);

  async function save(e: FormEvent) {
    e.preventDefault();
    if (d.emergency && !emergency && !window.confirm("Mark as EMERGENCY? It will need two different approvers and is flagged in the audit log.")) return;
    setBusy(true);
    setMsg(null);
    const r = await callApi(`/api/change-requests/${crId}/options`, "PATCH", {
      emergency: d.emergency,
      emergencyReason: d.emergency ? d.emergencyReason : null,
      rebootPolicy: d.rebootPolicy,
    });
    setBusy(false);
    if (!r.ok) return setMsg({ tone: "bad", text: r.error });
    setMsg({ tone: "good", text: "Saved." });
    start(() => router.refresh());
  }

  return (
    <form onSubmit={save} className="grid gap-4 md:grid-cols-2">
      <label className="flex items-start gap-2 text-sm text-fg md:col-span-2">
        <input type="checkbox" className="mt-0.5 h-4 w-4 accent-primary" checked={d.emergency} onChange={(e) => setD({ ...d, emergency: e.target.checked })} />
        <span>
          <span className="font-medium">Emergency change</span>
          <span className="block text-xs text-muted">
            Needs two different approvers (never you). It may deploy outside the maintenance window only if BOTH approvers choose “Approve &amp; deploy now”.
          </span>
        </span>
      </label>
      {d.emergency && (
        <label className={`${labelCls} md:col-span-2`}>
          Reason (required)
          <textarea className={inputCls} rows={2} minLength={10} maxLength={500} required value={d.emergencyReason} onChange={(e) => setD({ ...d, emergencyReason: e.target.value })} placeholder="Actively exploited CVE on internet-facing branch PCs" />
        </label>
      )}
      <label className={labelCls}>
        Reboot policy
        <select className={inputCls} value={d.rebootPolicy} onChange={(e) => setD({ ...d, rebootPolicy: e.target.value as RebootPolicyValue })}>
          {REBOOT_POLICIES.map((p) => (
            <option key={p} value={p}>{REBOOT_LABEL[p]}</option>
          ))}
        </select>
      </label>
      <div className="flex items-end">
        <button type="submit" disabled={busy} className={`${buttonBase} ${BUTTON.default}`}>
          {busy && <Loader2 size={15} className="animate-spin" />} Save options
        </button>
      </div>
      {msg && (
        <div className="md:col-span-2">
          <Alert tone={msg.tone}>{msg.text}</Alert>
        </div>
      )}
    </form>
  );
}
