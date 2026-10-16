"use client";

import { useState, type FormEvent, type ReactNode } from "react";
import { ArrowLeft, KeyRound, Loader2, LogIn } from "lucide-react";
import { callApi } from "@/components/api-client";
import { Alert, BUTTON, buttonBase, inputCls, labelCls } from "@/components/ui";

type View = { step: "password" } | { step: "change-password" };

type StepResponse = { step: "change-password" } | { step: "done"; redirect: string };

const RESTART_HINT = /expired|cancelled|start again|sign in again/i;
const PASSWORD_MIN = 14;

interface LocalLoginFormProps {
  returnTo: string;
}

/** Local sign-in (password only): password, then a forced password change when required. */
export function LocalLoginForm({ returnTo }: LocalLoginFormProps) {
  const [view, setView] = useState<View>({ step: "password" });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function send(url: string, body: unknown): Promise<void> {
    setBusy(true);
    setError(null);
    const r = await callApi<StepResponse>(url, "POST", body);
    if (!r.ok) {
      setBusy(false);
      setError(r.error);
      if (RESTART_HINT.test(r.error)) setView({ step: "password" });
      return;
    }
    if (r.data.step === "done") {
      window.location.assign(r.data.redirect); // full navigation: the new session cookie applies everywhere
      return;
    }
    setBusy(false);
    setView(r.data);
  }

  const restart = () => {
    setError(null);
    setView({ step: "password" });
  };

  return (
    <div className="space-y-5">
      {error && <Alert tone="bad">{error}</Alert>}
      {view.step === "password" && <PasswordStep busy={busy} onSubmit={(upn, password) => send("/api/auth/password", { upn, password, returnTo })} />}
      {view.step === "change-password" && <ChangePasswordStep busy={busy} onSubmit={(newPassword) => send("/api/auth/password/change", { newPassword })} onBack={restart} />}
    </div>
  );
}

function SubmitButton({ busy, label, icon, disabled = false }: { busy: boolean; label: string; icon: ReactNode; disabled?: boolean }) {
  return (
    <button type="submit" disabled={busy || disabled} className={`${buttonBase} ${BUTTON.primary} w-full`}>
      {busy ? <Loader2 size={16} className="animate-spin" aria-hidden /> : icon}
      {busy ? "Checking…" : label}
    </button>
  );
}

function BackLink({ onBack }: { onBack: () => void }) {
  return (
    <button type="button" onClick={onBack} className="inline-flex items-center gap-1 text-sm text-muted hover:text-fg">
      <ArrowLeft size={14} aria-hidden /> Start over
    </button>
  );
}

function PasswordStep({ busy, onSubmit }: { busy: boolean; onSubmit: (upn: string, password: string) => void }) {
  const [upn, setUpn] = useState("");
  const [password, setPassword] = useState("");
  function submit(e: FormEvent) {
    e.preventDefault();
    onSubmit(upn.trim(), password);
  }
  return (
    <form method="post" onSubmit={submit} className="space-y-4">
      <label className={labelCls}>
        Username
        <input
          className={inputCls}
          name="username"
          type="text"
          autoComplete="username"
          autoCapitalize="none"
          spellCheck={false}
          placeholder="name@bank.example"
          required
          maxLength={200}
          value={upn}
          onChange={(e) => setUpn(e.target.value)}
          autoFocus
        />
      </label>
      <label className={labelCls}>
        Password
        <input
          className={inputCls}
          name="password"
          type="password"
          autoComplete="current-password"
          required
          maxLength={1024}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
      </label>
      <SubmitButton busy={busy} label="Continue" icon={<LogIn size={16} aria-hidden />} />
    </form>
  );
}

function ChangePasswordStep({ busy, onSubmit, onBack }: { busy: boolean; onSubmit: (pw: string) => void; onBack: () => void }) {
  const [pw, setPw] = useState("");
  const [confirm, setConfirm] = useState("");
  const [local, setLocal] = useState<string | null>(null);
  function submit(e: FormEvent) {
    e.preventDefault();
    if (pw.length < PASSWORD_MIN) return setLocal(`Use at least ${PASSWORD_MIN} characters.`);
    if (pw !== confirm) return setLocal("The two passwords do not match.");
    setLocal(null);
    onSubmit(pw);
  }
  return (
    <form method="post" onSubmit={submit} className="space-y-4">
      <Alert tone="warn">You need a new password before you can continue — either you signed in with a temporary password, or your password has expired under your organisation’s policy. Choose a new password to finish signing in.</Alert>
      <ul className="list-disc space-y-0.5 pl-5 text-xs text-muted">
        <li>At least {PASSWORD_MIN} characters — a passphrase of several words works well.</li>
        <li>Not your username, not a common password, not the temporary one.</li>
      </ul>
      {local && <Alert tone="bad">{local}</Alert>}
      <label className={labelCls}>
        New password
        <input className={inputCls} type="password" name="new-password" autoComplete="new-password" required minLength={PASSWORD_MIN} maxLength={256} value={pw} onChange={(e) => setPw(e.target.value)} autoFocus />
      </label>
      <label className={labelCls}>
        Confirm new password
        <input className={inputCls} type="password" name="confirm-password" autoComplete="new-password" required maxLength={256} value={confirm} onChange={(e) => setConfirm(e.target.value)} />
      </label>
      <SubmitButton busy={busy} label="Set password and sign in" icon={<KeyRound size={16} aria-hidden />} />
      <BackLink onBack={onBack} />
    </form>
  );
}
