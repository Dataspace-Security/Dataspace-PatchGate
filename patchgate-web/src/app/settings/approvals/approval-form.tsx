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

export function ApprovalPolicyForm({ initial, readOnly = false }: { initial: Policy; readOnly?: boolean }) {
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
    if (
      changed.requireBankApproval === false &&
      !window.confirm("Switch approval OFF? Change requests of this bank will be approved on submit and can be deployed WITHOUT a second person. This is recorded in the audit log and every admin is notified.")
    ) {
      setBusy(false);
      return;
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
        <label className="flex items-start gap-3 text-sm text-fg md:col-span-2">
          <input
            type="checkbox"
            className="mt-0.5 h-4 w-4"
            checked={p.requireBankApproval}
            onChange={(e) => setP({ ...p, requireBankApproval: e.target.checked })}
            data-testid="approval-required"
          />
          <span>
            <span className="font-medium">Approval required</span>
            <span className="block text-xs text-muted">
              ON (recommended): every change request needs an admin of this bank other than the maker; emergency and large requests need two.
              OFF: an admin&apos;s request is approved on submit and can be deployed without a second person (recorded as auto-approved). Switching is audited and every admin is notified.
            </span>
          </span>
        </label>
        {!p.requireBankApproval && (
          <div className="md:col-span-2">
            <Alert tone="warn">Approval is OFF for this bank — requests deploy without a second person.</Alert>
          </div>
        )}
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
        {!readOnly && (
          <div className="md:col-span-2">
            <button type="submit" disabled={busy} className={`${buttonBase} ${BUTTON.primary}`}>
              {busy && <Loader2 size={15} className="animate-spin" />} Save policy
            </button>
          </div>
        )}
      </form>
    </Card>
  );
}
