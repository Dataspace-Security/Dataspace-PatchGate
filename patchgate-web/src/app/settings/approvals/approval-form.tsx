"use client";

import { useState, useTransition, type FormEvent } from "react";
import { useRouter } from "next/navigation";
import { Loader2 } from "lucide-react";
import { REBOOT_LABEL, REBOOT_POLICIES, type RebootPolicyValue } from "@/lib/policies/reboot-labels";
import { Alert, BUTTON, Card, buttonBase, inputCls, labelCls } from "@/components/ui";
import { send } from "../settings-client";

interface Policy {
  requireBankApproval: boolean;
  approvalExpiryDays: number;
  maxTargetsPerCr: number;
  defaultRebootPolicy: RebootPolicyValue;
  timezone: string;
}

export function ApprovalPolicyForm({ initial }: { initial: Policy }) {
  const router = useRouter();
  const [, start] = useTransition();
  const [p, setP] = useState<Policy>(initial);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ tone: "bad" | "good"; text: string } | null>(null);

  async function save(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setMsg(null);
    const changed = Object.fromEntries(Object.entries(p).filter(([k, v]) => initial[k as keyof Policy] !== v));
    if (Object.keys(changed).length === 0) {
      setBusy(false);
      return setMsg({ tone: "good", text: "Nothing to change." });
    }
    const r = await send("/api/settings/approvals", "PATCH", changed);
    setBusy(false);
    if (!r.ok) return setMsg({ tone: "bad", text: r.error });
    setMsg({ tone: "good", text: "Policy saved and recorded in the bank's audit log." });
    start(() => router.refresh());
  }

  return (
    <Card>
      <form onSubmit={save} className="grid gap-5 md:grid-cols-2">
        <div className="text-sm text-fg md:col-span-2">
          <span className="font-medium">Bank approval: always required</span>
          <span className="block text-xs text-muted">
            Every change request needs at least one approver or admin of this bank (never the maker). This is a platform rule and cannot be turned off.
          </span>
        </div>
        <label className={labelCls}>
          Approval expiry (days)
          <input className={inputCls} type="number" min={0} max={365} required value={p.approvalExpiryDays} onChange={(e) => setP({ ...p, approvalExpiryDays: Number(e.target.value) })} />
          <span className="mt-1 block text-xs font-normal text-muted">An approved request must be started within this many days (0 = never expires).</span>
        </label>
        <label className={labelCls}>
          Max endpoints per request with one approver
          <input className={inputCls} type="number" min={0} max={1000000} required value={p.maxTargetsPerCr} onChange={(e) => setP({ ...p, maxTargetsPerCr: Number(e.target.value) })} />
          <span className="mt-1 block text-xs font-normal text-muted">Requests targeting more PCs need a second, different approver (0 = no limit).</span>
        </label>
        <label className={labelCls}>
          Default reboot policy for new requests
          <select className={inputCls} value={p.defaultRebootPolicy} onChange={(e) => setP({ ...p, defaultRebootPolicy: e.target.value as RebootPolicyValue })}>
            {REBOOT_POLICIES.map((r) => (
              <option key={r} value={r}>{REBOOT_LABEL[r]}</option>
            ))}
          </select>
          <span className="mt-1 block text-xs font-normal text-muted">A ring can override it (Rings tab); the maker can change it on a draft.</span>
        </label>
        <label className={labelCls}>
          Bank timezone (IANA)
          <input className={`${inputCls} font-mono`} required maxLength={64} value={p.timezone} onChange={(e) => setP({ ...p, timezone: e.target.value })} spellCheck={false} />
          <span className="mt-1 block text-xs font-normal text-muted">Maintenance-window previews are shown in this timezone.</span>
        </label>
        {msg && (
          <div className="md:col-span-2">
            <Alert tone={msg.tone}>{msg.text}</Alert>
          </div>
        )}
        <div className="md:col-span-2">
          <button type="submit" disabled={busy} className={`${buttonBase} ${BUTTON.primary}`}>
            {busy && <Loader2 size={15} className="animate-spin" />} Save policy
          </button>
        </div>
      </form>
    </Card>
  );
}
