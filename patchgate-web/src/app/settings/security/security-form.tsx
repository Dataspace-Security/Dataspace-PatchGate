"use client";

import { useState, useTransition, type FormEvent } from "react";
import { useRouter } from "next/navigation";
import { Loader2 } from "lucide-react";
import { Alert, BUTTON, Card, buttonBase, inputCls, labelCls } from "@/components/ui";
import { send } from "../settings-client";

interface Values {
  passwordMaxAgeDays: number;
  inactivityDisableDays: number;
  maxSessionsPerUser: number;
}

export function SecurityPolicyForm({
  initial,
  sessionIdleMinutes,
  sessionMaxHours,
  readOnly = false,
}: {
  initial: Values;
  sessionIdleMinutes: number;
  sessionMaxHours: number;
  readOnly?: boolean;
}) {
  const router = useRouter();
  const [, start] = useTransition();
  const [v, setV] = useState<Values>(initial);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ tone: "bad" | "good"; text: string } | null>(null);

  async function save(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setMsg(null);
    const r = await send("/api/settings/security", "PATCH", v);
    setBusy(false);
    if (!r.ok) return setMsg({ tone: "bad", text: r.error });
    setMsg({ tone: "good", text: "Saved." });
    start(() => router.refresh());
  }

  const num = (k: keyof Values) => (e: React.ChangeEvent<HTMLInputElement>) => setV({ ...v, [k]: Number(e.target.value) });
  return (
    <Card>
      <form onSubmit={save} className="grid gap-5 md:grid-cols-3">
        <label className={labelCls}>
          Password max age (days)
          <input className={inputCls} type="number" min={0} max={3650} required value={v.passwordMaxAgeDays} onChange={num("passwordMaxAgeDays")} />
          <span className="mt-1 block text-xs font-normal text-muted">Older passwords must be changed at the next sign-in (0 = off).</span>
        </label>
        <label className={labelCls}>
          Disable after inactivity (days)
          <input className={inputCls} type="number" min={0} max={3650} required value={v.inactivityDisableDays} onChange={num("inactivityDisableDays")} />
          <span className="mt-1 block text-xs font-normal text-muted">Accounts without sign-in or administrator activity are deactivated (0 = off, else ≥ 7). At least one platform admin always stays active.</span>
        </label>
        <label className={labelCls}>
          Max concurrent sessions per user
          <input className={inputCls} type="number" min={0} max={100} required value={v.maxSessionsPerUser} onChange={num("maxSessionsPerUser")} />
          <span className="mt-1 block text-xs font-normal text-muted">A new sign-in revokes the oldest sessions beyond this (0 = unlimited).</span>
        </label>
        <div className="text-sm text-muted md:col-span-3">
          Session idle timeout <b className="text-fg">{sessionIdleMinutes} min</b> · absolute lifetime <b className="text-fg">{sessionMaxHours} h</b>{" "}
          <span className="text-xs">(read-only: SESSION_IDLE_MINUTES / SESSION_MAX_HOURS in the server environment)</span>
        </div>
        {msg && (
          <div className="md:col-span-3">
            <Alert tone={msg.tone}>{msg.text}</Alert>
          </div>
        )}
        {!readOnly && (
          <div className="md:col-span-3">
            <button type="submit" disabled={busy} className={`${buttonBase} ${BUTTON.primary}`}>
              {busy && <Loader2 size={15} className="animate-spin" />} Save policy
            </button>
          </div>
        )}
      </form>
    </Card>
  );
}
