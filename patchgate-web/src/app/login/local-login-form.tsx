"use client";

import { useState, type FormEvent, type ReactNode } from "react";
import { ArrowLeft, Check, Copy, KeyRound, Loader2, LogIn, ShieldCheck, Smartphone } from "lucide-react";
import { callApi } from "@/components/api-client";
import { Alert, BUTTON, buttonBase, inputCls, labelCls } from "@/components/ui";

type View =
  | { step: "password" }
  | { step: "verify" }
  | { step: "enroll"; secret: string; otpauthUri: string; qrSvgDataUrl: string }
  | { step: "change-password" };

type StepResponse =
  | { step: "verify" }
  | { step: "enroll"; secret: string; otpauthUri: string; qrSvgDataUrl: string }
  | { step: "change-password" }
  | { step: "done"; redirect: string };

const RESTART_HINT = /expired|cancelled|start again|sign in again/i;
const PASSWORD_MIN = 14;

interface LocalLoginFormProps {
  returnTo: string;
}

/** Local sign-in: password → authenticator (enrol on first use) → forced password change when required. */
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
      <StepIndicator view={view} />
      {error && <Alert tone="bad">{error}</Alert>}
      {view.step === "password" && <PasswordStep busy={busy} onSubmit={(upn, password) => send("/api/auth/password", { upn, password, returnTo })} />}
      {view.step === "verify" && (
        <CodeStep
          busy={busy}
          intro={
            <p className="text-sm text-muted">
              Open your authenticator app and enter the 6-digit code for <span className="font-medium text-fg">PatchGate</span>.
            </p>
          }
          submitLabel="Verify"
          onSubmit={(code) => send("/api/auth/totp", { code })}
          onBack={restart}
        />
      )}
      {view.step === "enroll" && (
        <CodeStep busy={busy} intro={<EnrollIntro view={view} />} submitLabel="Verify and continue" onSubmit={(code) => send("/api/auth/totp", { code })} onBack={restart} />
      )}
      {view.step === "change-password" && <ChangePasswordStep busy={busy} onSubmit={(newPassword) => send("/api/auth/password/change", { newPassword })} onBack={restart} />}
    </div>
  );
}

function StepIndicator({ view }: { view: View }) {
  const steps = [
    { key: "password", label: "Password", icon: KeyRound },
    { key: "mfa", label: "Authenticator", icon: Smartphone },
    ...(view.step === "change-password" ? [{ key: "change-password", label: "New password", icon: ShieldCheck }] : []),
  ];
  const current = view.step === "password" ? 0 : view.step === "change-password" ? 2 : 1;
  return (
    <ol className="flex items-center gap-2 text-xs" aria-label="Sign-in steps">
      {steps.map((s, i) => {
        const Icon = i < current ? Check : s.icon;
        const state = i < current ? "done" : i === current ? "current" : "todo";
        return (
          <li key={s.key} className="flex items-center gap-2" aria-current={state === "current" ? "step" : undefined}>
            {i > 0 && <span aria-hidden className="h-px w-5 bg-border-strong" />}
            <span
              className={`flex items-center gap-1.5 rounded-full px-2.5 py-1 font-medium ${
                state === "current" ? "bg-primary text-primary-fg" : state === "done" ? "bg-success-soft text-success" : "bg-neutral-soft text-muted"
              }`}
            >
              <Icon size={13} aria-hidden />
              {s.label}
            </span>
          </li>
        );
      })}
    </ol>
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

function EnrollIntro({ view }: { view: Extract<View, { step: "enroll" }> }) {
  const [copied, setCopied] = useState(false);
  async function copy() {
    try {
      await navigator.clipboard.writeText(view.secret.replace(/\s/g, ""));
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopied(false);
    }
  }
  return (
    <div className="space-y-4">
      <Alert tone="info">Two-factor authentication is mandatory. Set up an authenticator app (Microsoft Authenticator, Google Authenticator, FreeOTP…) to continue.</Alert>
      <ol className="list-decimal space-y-1 pl-5 text-sm text-muted">
        <li>In the app, add an account and scan this QR code.</li>
        <li>Enter the 6-digit code the app shows.</li>
      </ol>
      <div className="flex justify-center">
        {/* White tile so the code scans in dark mode too. */}
        {/* eslint-disable-next-line @next/next/no-img-element -- inline data: URL generated server-side */}
        <img src={view.qrSvgDataUrl} alt="QR code for your authenticator app" width={184} height={184} className="rounded-lg border border-border bg-white p-2" />
      </div>
      <div>
        <p className="text-xs text-muted">Can&apos;t scan? Enter this key manually (time-based, 6 digits):</p>
        <div className="mt-1 flex items-center gap-2">
          <code className="flex-1 select-all break-all rounded-lg bg-surface-2 px-3 py-2 font-mono text-sm tracking-wider text-fg">{view.secret}</code>
          <button type="button" onClick={copy} className={`${buttonBase} ${BUTTON.default}`} aria-label="Copy key">
            {copied ? <Check size={15} aria-hidden /> : <Copy size={15} aria-hidden />}
          </button>
        </div>
      </div>
    </div>
  );
}

function CodeStep({ busy, intro, submitLabel, onSubmit, onBack }: { busy: boolean; intro: ReactNode; submitLabel: string; onSubmit: (code: string) => void; onBack: () => void }) {
  const [code, setCode] = useState("");
  function submit(e: FormEvent) {
    e.preventDefault();
    onSubmit(code);
  }
  return (
    <form method="post" onSubmit={submit} className="space-y-4">
      {intro}
      <label className={labelCls}>
        Verification code
        <input
          className={`${inputCls} text-center font-mono text-2xl tracking-[0.5em]`}
          name="code"
          inputMode="numeric"
          autoComplete="one-time-code"
          pattern="\d{6}"
          maxLength={6}
          required
          placeholder="••••••"
          value={code}
          onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
          autoFocus
        />
      </label>
      <SubmitButton busy={busy} disabled={code.length !== 6} label={submitLabel} icon={<ShieldCheck size={16} aria-hidden />} />
      <BackLink onBack={onBack} />
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
