"use client";

import { useState, useTransition, type FormEvent } from "react";
import { useRouter } from "next/navigation";
import { Building2, Loader2, Pencil, Power } from "lucide-react";
import { callApi } from "@/components/api-client";
import { Alert, BUTTON, Card, buttonBase, inputCls, labelCls } from "@/components/ui";

interface BankDraft {
  name: string;
  slug: string;
  requireBankApproval: boolean;
}

function BankFields({ draft, onChange }: { draft: BankDraft; onChange: (d: BankDraft) => void }) {
  return (
    <>
      <label className={labelCls}>
        Bank name
        <input className={inputCls} required minLength={2} maxLength={120} value={draft.name} onChange={(e) => onChange({ ...draft, name: e.target.value })} />
      </label>
      <label className={labelCls}>
        Short code
        <input
          className={`${inputCls} font-mono`}
          required
          pattern="[a-z0-9](?:[a-z0-9\-]{0,38}[a-z0-9])?"
          title="2–40 lower-case letters, digits or dashes"
          placeholder="bank-a"
          maxLength={40}
          spellCheck={false}
          value={draft.slug}
          onChange={(e) => onChange({ ...draft, slug: e.target.value.toLowerCase() })}
        />
      </label>
      <p className="text-xs text-muted md:col-span-2">
        New banks start with approval ON (a bank admin other than the maker approves). An admin can switch it in Settings → Approval policy.
      </p>
    </>
  );
}

export function CreateBankForm() {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [draft, setDraft] = useState<BankDraft>({ name: "", slug: "", requireBankApproval: true });

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    const r = await callApi("/api/admin/tenants", "POST", { ...draft, active: true });
    setBusy(false);
    if (!r.ok) return setError(r.error);
    setDraft({ name: "", slug: "", requireBankApproval: true });
    setOpen(false);
    router.refresh();
  }

  if (!open) {
    return (
      <button type="button" onClick={() => setOpen(true)} className={`${buttonBase} ${BUTTON.primary}`}>
        <Building2 size={16} aria-hidden /> New bank
      </button>
    );
  }
  return (
    <Card title="New bank" description="After creating the bank, add its first bank admin under Users.">
      <form method="post" onSubmit={submit} className="grid gap-4 md:grid-cols-2">
        <BankFields draft={draft} onChange={setDraft} />
        {error && (
          <div className="md:col-span-2">
            <Alert tone="bad">{error}</Alert>
          </div>
        )}
        <div className="flex gap-2 md:col-span-2">
          <button type="submit" disabled={busy} className={`${buttonBase} ${BUTTON.primary}`}>
            {busy && <Loader2 size={15} className="animate-spin" aria-hidden />}
            Create bank
          </button>
          <button type="button" onClick={() => setOpen(false)} className={`${buttonBase} ${BUTTON.default}`}>
            Cancel
          </button>
        </div>
      </form>
    </Card>
  );
}

interface BankRow extends BankDraft {
  id: string;
  active: boolean;
}

export function BankRowActions({ bank }: { bank: BankRow }) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [busy, setBusy] = useState(false);
  const [editing, setEditing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [draft, setDraft] = useState<BankDraft>({ name: bank.name, slug: bank.slug, requireBankApproval: bank.requireBankApproval });

  async function patch(body: Partial<BankRow>, confirmText?: string) {
    if (confirmText && !window.confirm(confirmText)) return;
    setBusy(true);
    setError(null);
    const r = await callApi(`/api/admin/tenants/${encodeURIComponent(bank.id)}`, "PATCH", body);
    setBusy(false);
    if (!r.ok) return setError(r.error);
    setEditing(false);
    startTransition(() => router.refresh());
  }

  const working = busy || pending;
  const small = "px-2.5 py-1.5 text-xs";

  if (editing) {
    return (
      <form method="post"
        className="grid gap-3 text-left md:grid-cols-2"
        onSubmit={(e) => {
          e.preventDefault();
          void patch({ name: draft.name, slug: draft.slug });
        }}
      >
        <BankFields draft={draft} onChange={setDraft} />
        {error && (
          <div className="md:col-span-2">
            <Alert tone="bad">{error}</Alert>
          </div>
        )}
        <div className="flex justify-end gap-2 md:col-span-2">
          <button type="submit" disabled={working} className={`${buttonBase} ${BUTTON.primary} ${small}`}>
            Save
          </button>
          <button type="button" onClick={() => setEditing(false)} className={`${buttonBase} ${BUTTON.default} ${small}`}>
            Cancel
          </button>
        </div>
      </form>
    );
  }

  return (
    <div className="flex flex-col items-end gap-1">
      <div className="flex justify-end gap-1.5">
        {working && <Loader2 size={15} className="mt-1.5 animate-spin text-muted" aria-label="Working" />}
        <button type="button" disabled={working} onClick={() => setEditing(true)} className={`${buttonBase} ${BUTTON.default} ${small}`}>
          <Pencil size={13} aria-hidden /> Edit
        </button>
        {bank.active ? (
          <button
            type="button"
            disabled={working}
            onClick={() => patch({ active: false }, `Deactivate ${bank.name}? All of its users are signed out and cannot sign in until the bank is reactivated.`)}
            className={`${buttonBase} ${BUTTON.danger} ${small}`}
          >
            <Power size={13} aria-hidden /> Deactivate
          </button>
        ) : (
          <button type="button" disabled={working} onClick={() => patch({ active: true })} className={`${buttonBase} ${BUTTON.default} ${small}`}>
            <Power size={13} aria-hidden /> Reactivate
          </button>
        )}
      </div>
      {error && (
        <span role="alert" className="max-w-xs text-xs text-danger">
          {error}
        </span>
      )}
    </div>
  );
}
