"use client";

import { useState, useTransition, type FormEvent } from "react";
import { useRouter } from "next/navigation";
import { Check, Copy, KeyRound, Loader2, Lock, Pencil, Power, ShieldOff, UserPlus, X } from "lucide-react";
import { callApi } from "@/components/api-client";
import { Alert, BUTTON, Card, buttonBase, inputCls, labelCls } from "@/components/ui";
import { ROLE_LABEL, roleOptions, type ActiveRole, type Role, type RoleScope } from "@/lib/auth/roles";

const PLATFORM = "__platform__";

interface BankOption {
  id: string;
  name: string;
  active: boolean;
}

interface Secret {
  upn: string;
  password: string;
  reason: "created" | "reset";
}

/** One-time display of a temporary password: never stored in clear, never shown again. */
function TemporaryPassword({ secret, onClose }: { secret: Secret; onClose: () => void }) {
  const [copied, setCopied] = useState(false);
  async function copy() {
    try {
      await navigator.clipboard.writeText(secret.password);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  }
  return (
    <div role="alert" className="rounded-xl border border-warning/40 bg-warning-soft p-4 text-sm">
      <div className="flex items-start justify-between gap-3">
        <div className="space-y-2">
          <p className="font-semibold text-warning">
            {secret.reason === "created" ? "User created" : "Password reset"} — temporary password for <span className="font-mono">{secret.upn}</span>
          </p>
          <div className="flex items-center gap-2">
            <code className="select-all rounded-lg bg-surface px-3 py-2 font-mono text-base tracking-wide text-fg ring-1 ring-border">{secret.password}</code>
            <button type="button" onClick={copy} className={`${buttonBase} ${BUTTON.default}`} aria-label="Copy temporary password">
              {copied ? <Check size={15} aria-hidden /> : <Copy size={15} aria-hidden />}
            </button>
          </div>
          <p className="text-xs text-muted">
            Shown <b>once</b>. Hand it over through a separate, trusted channel. The user must change it and set up an authenticator at first sign-in.
          </p>
        </div>
        <button type="button" onClick={onClose} className="rounded-lg p-1 text-muted hover:bg-surface hover:text-fg" aria-label="Dismiss">
          <X size={16} aria-hidden />
        </button>
      </div>
    </div>
  );
}

/** Platform admins only (the page renders it for nobody else; the API refuses everyone else). */
export function CreateUserForm({ banks }: { banks: BankOption[] }) {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [secret, setSecret] = useState<Secret | null>(null);
  const [form, setForm] = useState({ upn: "", name: "", role: "AUDITOR" as ActiveRole, bank: banks.find((b) => b.active)?.id ?? PLATFORM });
  const scope: RoleScope = form.bank === PLATFORM ? "platform" : "bank";
  const options = roleOptions(scope);
  const chosen = options.find((o) => o.value === form.role);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    const body = { upn: form.upn, name: form.name, role: form.role, tenantId: form.bank === PLATFORM ? null : form.bank };
    const r = await callApi<{ user: { upn: string }; temporaryPassword: string }>("/api/admin/users", "POST", body);
    setBusy(false);
    if (!r.ok) return setError(r.error);
    setSecret({ upn: r.data.user.upn, password: r.data.temporaryPassword, reason: "created" });
    setForm((f) => ({ ...f, upn: "", name: "" }));
    setOpen(false);
    router.refresh();
  }

  return (
    <div className="space-y-4">
      {secret && <TemporaryPassword secret={secret} onClose={() => setSecret(null)} />}
      {!open ? (
        <button type="button" onClick={() => setOpen(true)} className={`${buttonBase} ${BUTTON.primary}`}>
          <UserPlus size={16} aria-hidden /> New user
        </button>
      ) : (
        <Card title="New user" description="Choose the bank — or our team for PatchGate staff.">
          <form method="post" onSubmit={submit} className="grid gap-4 md:grid-cols-2">
            <label className={labelCls}>
              Sign-in name (UPN)
              <input className={inputCls} required maxLength={200} placeholder="name@bank.example" autoComplete="off" spellCheck={false} value={form.upn} onChange={(e) => setForm({ ...form, upn: e.target.value })} />
            </label>
            <label className={labelCls}>
              Full name
              <input className={inputCls} required maxLength={120} value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
            </label>
            <label className={labelCls}>
              Role
              <select className={inputCls} value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value as ActiveRole })}>
                {options.map((r) => (
                  <option key={r.value} value={r.value}>
                    {r.label}
                  </option>
                ))}
              </select>
              {chosen && <span className="mt-1 block text-xs font-normal text-muted">{chosen.description}</span>}
            </label>
            <label className={labelCls}>
              Bank
              <select className={inputCls} value={form.bank} onChange={(e) => setForm({ ...form, bank: e.target.value })}>
                <option value={PLATFORM}>PatchGate team (all banks)</option>
                {banks.map((b) => (
                  <option key={b.id} value={b.id} disabled={!b.active}>
                    {b.name}
                    {b.active ? "" : " (inactive)"}
                  </option>
                ))}
              </select>
            </label>
            {form.bank === PLATFORM && form.role === "ADMIN" && (
              <div className="md:col-span-2">
                <Alert tone="warn">A PatchGate-team admin can manage every bank and every user.</Alert>
              </div>
            )}
            {error && (
              <div className="md:col-span-2">
                <Alert tone="bad">{error}</Alert>
              </div>
            )}
            <div className="flex gap-2 md:col-span-2">
              <button type="submit" disabled={busy} className={`${buttonBase} ${BUTTON.primary}`}>
                {busy ? <Loader2 size={15} className="animate-spin" aria-hidden /> : <UserPlus size={15} aria-hidden />}
                Create user
              </button>
              <button type="button" onClick={() => setOpen(false)} className={`${buttonBase} ${BUTTON.default}`}>
                Cancel
              </button>
            </div>
          </form>
        </Card>
      )}
    </div>
  );
}

interface RowUser {
  id: string;
  upn: string;
  name: string;
  role: Role;
  active: boolean;
  locked: boolean;
}

/** Per-row actions for platform admins: edit name/role, reset password / MFA, unlock, deactivate / reactivate. */
export function UserActions({ user, self, bankUser }: { user: RowUser; self: boolean; bankUser: boolean }) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [secret, setSecret] = useState<Secret | null>(null);
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState({ name: user.name, role: user.role });

  async function run(url: string, method: "POST" | "PATCH", body: unknown, confirmText?: string) {
    if (confirmText && !window.confirm(confirmText)) return;
    setBusy(true);
    setError(null);
    const r = await callApi<{ temporaryPassword?: string | null }>(url, method, body);
    setBusy(false);
    if (!r.ok) return setError(r.error);
    if (r.data?.temporaryPassword) setSecret({ upn: user.upn, password: r.data.temporaryPassword, reason: "reset" });
    setEditing(false);
    startTransition(() => router.refresh());
  }

  const working = busy || pending;
  const base = `/api/admin/users/${encodeURIComponent(user.id)}`;
  const iconBtn = `${buttonBase} ${BUTTON.default} px-2.5 py-1.5 text-xs`;

  return (
    <div className="flex flex-col items-end gap-2">
      {editing ? (
        <form method="post"
          className="flex flex-wrap items-end justify-end gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            void run(base, "PATCH", { name: draft.name, role: draft.role });
          }}
        >
          <input className={`${inputCls} mt-0 w-40`} aria-label="Full name" required maxLength={120} value={draft.name} onChange={(e) => setDraft({ ...draft, name: e.target.value })} />
          <select className={`${inputCls} mt-0 w-36`} aria-label="Role" value={draft.role} disabled={self} onChange={(e) => setDraft({ ...draft, role: e.target.value as Role })}>
            {roleOptions(bankUser ? "bank" : "platform").map((r) => (
              <option key={r.value} value={r.value} title={r.description}>
                {ROLE_LABEL[r.value]}
              </option>
            ))}
          </select>
          <button type="submit" disabled={working} className={`${buttonBase} ${BUTTON.primary} px-2.5 py-1.5 text-xs`}>
            Save
          </button>
          <button type="button" onClick={() => setEditing(false)} className={iconBtn}>
            Cancel
          </button>
        </form>
      ) : (
        <div className="flex flex-wrap justify-end gap-1.5">
          {working && <Loader2 size={15} className="mt-1.5 animate-spin text-muted" aria-label="Working" />}
          <button type="button" className={iconBtn} disabled={working} onClick={() => setEditing(true)} title="Edit name or role">
            <Pencil size={13} aria-hidden /> Edit
          </button>
          {user.active && (
            <>
              <button
                type="button"
                className={iconBtn}
                disabled={working}
                title="Issue a new temporary password"
                onClick={() => run(`${base}/reset-password`, "POST", {}, `Reset the password of ${user.upn}? Their sessions end and they must sign in with a new temporary password.`)}
              >
                <KeyRound size={13} aria-hidden /> Reset password
              </button>
              <button
                type="button"
                className={iconBtn}
                disabled={working}
                title="Force authenticator re-enrolment"
                onClick={() => run(`${base}/reset-mfa`, "POST", {}, `Reset the authenticator of ${user.upn}? They will set up a new one at next sign-in.`)}
              >
                <ShieldOff size={13} aria-hidden /> Reset MFA
              </button>
            </>
          )}
          {user.locked && (
            <button type="button" className={iconBtn} disabled={working} onClick={() => run(`${base}/unlock`, "POST", {})}>
              <Lock size={13} aria-hidden /> Unlock
            </button>
          )}
          {!self &&
            (user.active ? (
              <button
                type="button"
                className={`${buttonBase} ${BUTTON.danger} px-2.5 py-1.5 text-xs`}
                disabled={working}
                onClick={() => run(base, "PATCH", { active: false }, `Deactivate ${user.upn}? All of their sessions end immediately.`)}
              >
                <Power size={13} aria-hidden /> Deactivate
              </button>
            ) : (
              <button type="button" className={iconBtn} disabled={working} onClick={() => run(base, "PATCH", { active: true })}>
                <Power size={13} aria-hidden /> Reactivate
              </button>
            ))}
        </div>
      )}
      {error && (
        <span role="alert" className="max-w-xs text-left text-xs text-danger">
          {error}
        </span>
      )}
      {secret && (
        <div className="w-full max-w-md text-left">
          <TemporaryPassword secret={secret} onClose={() => setSecret(null)} />
        </div>
      )}
    </div>
  );
}
