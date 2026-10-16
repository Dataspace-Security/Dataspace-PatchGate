"use client";

import { useEffect, useState, useTransition, type FormEvent } from "react";
import { useRouter } from "next/navigation";
import { CalendarClock, Loader2, Pencil, Trash2 } from "lucide-react";
import { REBOOT_LABEL, REBOOT_POLICIES, type RebootPolicyValue } from "@/lib/policies/reboot-labels";
import { Alert, BUTTON, Card, buttonBase, inputCls, labelCls } from "@/components/ui";
import { send } from "../settings-client";

interface WindowDraft {
  name: string;
  ringId: string;
  cron: string;
  durationMin: number;
  timezone: string;
  rebootPolicy: RebootPolicyValue;
}

interface Existing extends WindowDraft {
  id: string;
  inUse: boolean;
}

interface Occurrence {
  startLocal: string;
  endLocal: string;
}

const PREVIEW_DEBOUNCE_MS = 400;

/** Live validation + next 5 occurrences (server-side cron-parser, shown in the bank's timezone). */
function usePreview(d: Pick<WindowDraft, "cron" | "durationMin" | "timezone">, enabled: boolean) {
  const [state, setState] = useState<{ occurrences: Occurrence[]; error: string | null; loading: boolean }>({ occurrences: [], error: null, loading: false });
  useEffect(() => {
    if (!enabled) return;
    let cancelled = false;
    const t = setTimeout(async () => {
      setState((s) => ({ ...s, loading: true }));
      const r = await send<{ occurrences: Occurrence[] }>("/api/settings/windows/preview", "POST", d);
      if (cancelled) return;
      setState(r.ok ? { occurrences: r.data.occurrences, error: null, loading: false } : { occurrences: [], error: r.error, loading: false });
    }, PREVIEW_DEBOUNCE_MS);
    return () => {
      cancelled = true;
      clearTimeout(t);
    };
  }, [d.cron, d.durationMin, d.timezone, enabled]); // eslint-disable-line react-hooks/exhaustive-deps
  return state;
}

export function WindowEditor({ rings, bankTimezone, existing }: { rings: { id: string; name: string }[]; bankTimezone: string; existing?: Existing }) {
  const router = useRouter();
  const [, start] = useTransition();
  const [open, setOpen] = useState(false);
  const [draft, setDraft] = useState<WindowDraft>(
    existing ?? { name: "", ringId: rings[0]?.id ?? "", cron: "0 2 * * 0", durationMin: 120, timezone: bankTimezone, rebootPolicy: "REQUIRED" },
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const preview = usePreview(draft, open);

  async function save(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    const r = existing ? await send(`/api/settings/windows/${existing.id}`, "PATCH", draft) : await send("/api/settings/windows", "POST", draft);
    setBusy(false);
    if (!r.ok) return setError(r.error);
    setOpen(false);
    start(() => router.refresh());
  }

  async function remove() {
    if (!existing || !window.confirm(`Delete maintenance window ${existing.name}?`)) return;
    setBusy(true);
    const r = await send(`/api/settings/windows/${existing.id}`, "DELETE");
    setBusy(false);
    if (!r.ok) return setError(r.error);
    start(() => router.refresh());
  }

  if (!open) {
    return existing ? (
      <span className="inline-flex flex-col items-end gap-1">
        <span className="inline-flex gap-1">
          <button type="button" aria-label={`Edit ${existing.name}`} onClick={() => setOpen(true)} className={`${buttonBase} ${BUTTON.default} px-2`}>
            <Pencil size={14} />
          </button>
          <button
            type="button"
            aria-label={`Delete ${existing.name}`}
            title={existing.inUse ? "Used by change requests (kept for the audit trail)" : "Delete"}
            disabled={busy || existing.inUse}
            onClick={remove}
            className={`${buttonBase} ${BUTTON.danger} px-2`}
          >
            <Trash2 size={14} />
          </button>
        </span>
        {error && <span role="alert" className="max-w-xs text-xs text-danger">{error}</span>}
      </span>
    ) : (
      <button type="button" onClick={() => setOpen(true)} disabled={rings.length === 0} className={`${buttonBase} ${BUTTON.primary}`}>
        <CalendarClock size={16} aria-hidden /> New window
      </button>
    );
  }

  return (
    <div className="text-left">
      <Card title={existing ? `Edit ${existing.name}` : "New maintenance window"} description={existing?.inUse ? "Used by change requests: the schedule is locked while one is pending, approved or deploying." : undefined}>
        <form onSubmit={save} className="grid gap-4 md:grid-cols-3">
          <label className={labelCls}>
            Name
            <input className={inputCls} required minLength={2} maxLength={120} value={draft.name} onChange={(e) => setDraft({ ...draft, name: e.target.value })} placeholder="Sunday 02:00–04:00" />
          </label>
          <label className={labelCls}>
            Ring
            <select className={inputCls} value={draft.ringId} onChange={(e) => setDraft({ ...draft, ringId: e.target.value })}>
              {rings.map((r) => (
                <option key={r.id} value={r.id}>{r.name}</option>
              ))}
            </select>
          </label>
          <label className={labelCls} title="New change requests carry their own reboot policy (ring override, else the bank default); this applies only to older requests without one.">
            Reboot (fallback)
            <select className={inputCls} value={draft.rebootPolicy} onChange={(e) => setDraft({ ...draft, rebootPolicy: e.target.value as RebootPolicyValue })}>
              {REBOOT_POLICIES.map((p) => (
                <option key={p} value={p}>{REBOOT_LABEL[p]}</option>
              ))}
            </select>
          </label>
          <label className={labelCls}>
            Start (cron: min hour day month weekday)
            <input className={`${inputCls} font-mono`} required maxLength={100} value={draft.cron} onChange={(e) => setDraft({ ...draft, cron: e.target.value })} spellCheck={false} />
          </label>
          <label className={labelCls}>
            Duration (minutes)
            <input className={inputCls} type="number" required min={15} max={1440} value={draft.durationMin} onChange={(e) => setDraft({ ...draft, durationMin: Number(e.target.value) })} />
          </label>
          <label className={labelCls}>
            Timezone (IANA)
            <input className={`${inputCls} font-mono`} required maxLength={64} value={draft.timezone} onChange={(e) => setDraft({ ...draft, timezone: e.target.value })} spellCheck={false} />
          </label>
          <div className="md:col-span-3">
            <div className="text-xs font-semibold uppercase tracking-wide text-muted">Next 5 occurrences ({bankTimezone})</div>
            {preview.loading ? (
              <Loader2 size={15} className="mt-2 animate-spin text-muted" />
            ) : preview.error ? (
              <p className="mt-1 text-sm text-danger">{preview.error}</p>
            ) : (
              <ol className="mt-1 list-decimal pl-5 text-sm text-fg">
                {preview.occurrences.map((o) => (
                  <li key={o.startLocal}>
                    {o.startLocal} → {o.endLocal}
                  </li>
                ))}
              </ol>
            )}
          </div>
          {error && (
            <div className="md:col-span-3">
              <Alert tone="bad">{error}</Alert>
            </div>
          )}
          <div className="flex gap-2 md:col-span-3">
            <button type="submit" disabled={busy || !!preview.error} className={`${buttonBase} ${BUTTON.primary}`}>
              {busy && <Loader2 size={15} className="animate-spin" />} {existing ? "Save window" : "Create window"}
            </button>
            <button type="button" onClick={() => setOpen(false)} className={`${buttonBase} ${BUTTON.default}`}>
              Cancel
            </button>
          </div>
        </form>
      </Card>
    </div>
  );
}
