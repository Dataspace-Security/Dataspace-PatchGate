"use client";

import { useState, useTransition, type FormEvent } from "react";
import { useRouter } from "next/navigation";
import { ArrowDown, ArrowUp, Layers, Loader2, Pencil, Search, Trash2 } from "lucide-react";
import { REBOOT_LABEL, REBOOT_POLICIES, type RebootPolicyValue } from "@/lib/policies/reboot-labels";
import { Alert, BUTTON, Card, buttonBase, inputCls, labelCls } from "@/components/ui";
import { send } from "../settings-client";

function useRefresh() {
  const router = useRouter();
  const [pending, start] = useTransition();
  return { pending, refresh: () => start(() => router.refresh()) };
}

function RebootSelect({ value, onChange, allowDefault }: { value: RebootPolicyValue | null; onChange: (v: RebootPolicyValue | null) => void; allowDefault: boolean }) {
  return (
    <select className={inputCls} value={value ?? ""} onChange={(e) => onChange(e.target.value === "" ? null : (e.target.value as RebootPolicyValue))}>
      {allowDefault && <option value="">Bank default</option>}
      {REBOOT_POLICIES.map((p) => (
        <option key={p} value={p}>
          {REBOOT_LABEL[p]}
        </option>
      ))}
    </select>
  );
}

export function CreateRingForm() {
  const { refresh } = useRefresh();
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [rebootPolicy, setRebootPolicy] = useState<RebootPolicyValue | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    const r = await send("/api/settings/rings", "POST", { name, rebootPolicy });
    setBusy(false);
    if (!r.ok) return setError(r.error);
    setName("");
    setOpen(false);
    refresh();
  }

  if (!open) {
    return (
      <button type="button" onClick={() => setOpen(true)} className={`${buttonBase} ${BUTTON.primary}`}>
        <Layers size={16} aria-hidden /> New ring
      </button>
    );
  }
  return (
    <Card title="New ring" description="Added at the end of the rollout order. The WSUS group defaults to the ring name.">
      <form onSubmit={submit} className="grid gap-4 md:grid-cols-2">
        <label className={labelCls}>
          Name
          <input className={inputCls} required minLength={2} maxLength={64} value={name} onChange={(e) => setName(e.target.value)} placeholder="Ring3-Branches" />
        </label>
        <label className={labelCls}>
          Reboot default
          <RebootSelect value={rebootPolicy} onChange={setRebootPolicy} allowDefault />
        </label>
        {error && (
          <div className="md:col-span-2">
            <Alert tone="bad">{error}</Alert>
          </div>
        )}
        <div className="flex gap-2 md:col-span-2">
          <button type="submit" disabled={busy} className={`${buttonBase} ${BUTTON.primary}`}>
            {busy && <Loader2 size={15} className="animate-spin" />} Create ring
          </button>
          <button type="button" onClick={() => setOpen(false)} className={`${buttonBase} ${BUTTON.default}`}>
            Cancel
          </button>
        </div>
      </form>
    </Card>
  );
}

interface RingRow {
  id: string;
  name: string;
  wsusGroup: string;
  rebootPolicy: RebootPolicyValue | null;
  deletable: boolean;
}

export function RingRowActions({ ring, order, index }: { ring: RingRow; order: string[]; index: number }) {
  const { pending, refresh } = useRefresh();
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState({ name: ring.name, wsusGroup: ring.wsusGroup, rebootPolicy: ring.rebootPolicy });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function run(url: string, method: "PATCH" | "PUT" | "DELETE", body?: unknown) {
    setBusy(true);
    setError(null);
    const r = await send(url, method, body);
    setBusy(false);
    if (!r.ok) return setError(r.error);
    setEditing(false);
    refresh();
  }

  function move(delta: -1 | 1) {
    const next = [...order];
    const j = index + delta;
    [next[index], next[j]] = [next[j]!, next[index]!];
    void run("/api/settings/rings/order", "PUT", { ringIds: next });
  }

  const working = busy || pending;
  if (editing) {
    return (
      <div className="ml-auto grid max-w-sm gap-2 text-left">
        <input className={inputCls} aria-label="Ring name" value={draft.name} onChange={(e) => setDraft({ ...draft, name: e.target.value })} />
        <input className={`${inputCls} font-mono`} aria-label="WSUS group" value={draft.wsusGroup} onChange={(e) => setDraft({ ...draft, wsusGroup: e.target.value })} />
        <RebootSelect value={draft.rebootPolicy} onChange={(v) => setDraft({ ...draft, rebootPolicy: v })} allowDefault />
        <div className="flex justify-end gap-2">
          <button type="button" disabled={working} onClick={() => run(`/api/settings/rings/${ring.id}`, "PATCH", draft)} className={`${buttonBase} ${BUTTON.primary}`}>
            Save
          </button>
          <button type="button" onClick={() => setEditing(false)} className={`${buttonBase} ${BUTTON.default}`}>
            Cancel
          </button>
        </div>
        {error && <span className="text-xs text-danger">{error}</span>}
      </div>
    );
  }
  return (
    <span className="inline-flex flex-col items-end gap-1">
      <span className="inline-flex gap-1">
        <button type="button" title="Move up" aria-label={`Move ${ring.name} up`} disabled={working || index === 0} onClick={() => move(-1)} className={`${buttonBase} ${BUTTON.default} px-2`}>
          <ArrowUp size={14} />
        </button>
        <button type="button" title="Move down" aria-label={`Move ${ring.name} down`} disabled={working || index === order.length - 1} onClick={() => move(1)} className={`${buttonBase} ${BUTTON.default} px-2`}>
          <ArrowDown size={14} />
        </button>
        <button type="button" title="Edit" aria-label={`Edit ${ring.name}`} disabled={working} onClick={() => setEditing(true)} className={`${buttonBase} ${BUTTON.default} px-2`}>
          <Pencil size={14} />
        </button>
        <button
          type="button"
          title={ring.deletable ? "Delete" : "Only empty rings (no endpoints, no change requests) can be deleted"}
          aria-label={`Delete ${ring.name}`}
          disabled={working || !ring.deletable}
          onClick={() => window.confirm(`Delete ring ${ring.name}? Its maintenance windows are deleted too.`) && run(`/api/settings/rings/${ring.id}`, "DELETE")}
          className={`${buttonBase} ${BUTTON.danger} px-2`}
        >
          <Trash2 size={14} />
        </button>
      </span>
      {error && <span role="alert" className="max-w-xs text-xs text-danger">{error}</span>}
    </span>
  );
}

export function BulkAssignPanel({ rings, sites }: { rings: { id: string; name: string }[]; sites: string[] }) {
  const { refresh } = useRefresh();
  const [filter, setFilter] = useState({ site: "", hostnamePattern: "", fromRingId: "" });
  const [ringId, setRingId] = useState<string>(rings[0]?.id ?? "");
  const [preview, setPreview] = useState<{ count: number; sample: string[] } | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ tone: "bad" | "good"; text: string } | null>(null);

  const cleanFilter = () => ({
    ...(filter.site ? { site: filter.site } : {}),
    ...(filter.hostnamePattern ? { hostnamePattern: filter.hostnamePattern } : {}),
    ...(filter.fromRingId ? { fromRingId: filter.fromRingId } : {}),
  });

  async function doPreview(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setMessage(null);
    const r = await send<{ count: number; sample: string[] }>("/api/settings/rings/bulk-assign", "POST", { mode: "preview", filter: cleanFilter() });
    setBusy(false);
    if (!r.ok) return setMessage({ tone: "bad", text: r.error });
    setPreview(r.data);
  }

  async function confirm() {
    if (!preview) return;
    const target = ringId === "" ? "no ring (unassigned)" : (rings.find((x) => x.id === ringId)?.name ?? "the ring");
    if (!window.confirm(`Move ${preview.count} endpoint(s) to ${target}? This is recorded in the audit log.`)) return;
    setBusy(true);
    const r = await send<{ matched: number; moved: number }>("/api/settings/rings/bulk-assign", "POST", {
      mode: "confirm",
      filter: cleanFilter(),
      ringId: ringId === "" ? null : ringId,
      expectedCount: preview.count,
    });
    setBusy(false);
    if (!r.ok) return setMessage({ tone: "bad", text: r.error });
    setMessage({ tone: "good", text: `${r.data.moved} endpoint(s) moved (${r.data.matched} matched).` });
    setPreview(null);
    refresh();
  }

  return (
    <Card title="Bulk-assign endpoints to a ring" description="Filter by branch and/or hostname pattern (* and ? wildcards), preview the count, then confirm. Submitted change requests keep their approved targets.">
      <form onSubmit={doPreview} className="grid gap-4 md:grid-cols-4">
        <label className={labelCls}>
          Branch / site
          <select className={inputCls} value={filter.site} onChange={(e) => { setFilter({ ...filter, site: e.target.value }); setPreview(null); }}>
            <option value="">Any</option>
            {sites.map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
        </label>
        <label className={labelCls}>
          Hostname pattern
          <input className={`${inputCls} font-mono`} placeholder="BR-PUNE-*" maxLength={100} value={filter.hostnamePattern} onChange={(e) => { setFilter({ ...filter, hostnamePattern: e.target.value }); setPreview(null); }} />
        </label>
        <label className={labelCls}>
          Currently in
          <select className={inputCls} value={filter.fromRingId} onChange={(e) => { setFilter({ ...filter, fromRingId: e.target.value }); setPreview(null); }}>
            <option value="">Any ring</option>
            <option value="none">No ring</option>
            {rings.map((r) => (
              <option key={r.id} value={r.id}>{r.name}</option>
            ))}
          </select>
        </label>
        <label className={labelCls}>
          Move to
          <select className={inputCls} value={ringId} onChange={(e) => setRingId(e.target.value)}>
            {rings.map((r) => (
              <option key={r.id} value={r.id}>{r.name}</option>
            ))}
            <option value="">No ring (unassign)</option>
          </select>
        </label>
        <div className="flex flex-wrap items-center gap-2 md:col-span-4">
          <button type="submit" disabled={busy} className={`${buttonBase} ${BUTTON.default}`}>
            <Search size={15} /> Preview
          </button>
          {preview && (
            <button type="button" disabled={busy || preview.count === 0} onClick={confirm} className={`${buttonBase} ${BUTTON.primary}`}>
              Move {preview.count} endpoint{preview.count === 1 ? "" : "s"}
            </button>
          )}
          {busy && <Loader2 size={15} className="animate-spin text-muted" />}
        </div>
      </form>
      {preview && (
        <p className="mt-3 text-sm text-muted">
          <b className="text-fg">{preview.count}</b> match{preview.count === 1 ? "es" : ""}
          {preview.sample.length > 0 && <>: <span className="font-mono text-xs">{preview.sample.join(", ")}{preview.count > preview.sample.length ? ", …" : ""}</span></>}
        </p>
      )}
      {message && (
        <div className="mt-3">
          <Alert tone={message.tone}>{message.text}</Alert>
        </div>
      )}
    </Card>
  );
}
