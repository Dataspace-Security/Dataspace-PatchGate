"use client";

import { useState, type FormEvent } from "react";
import { useRouter } from "next/navigation";
import { KeyRound, Loader2, LogOut } from "lucide-react";
import { callApi } from "@/components/api-client";
import { Alert, BUTTON, buttonBase, inputCls, labelCls } from "@/components/ui";

interface ChangePasswordFormProps {
  minLength: number;
  upn: string;
}

interface RevokeResult {
  revokedSessions: number;
}

const SIGNED_OUT = /signed out|not signed in|session expired/i;
const plural = (n: number) => `${n} other session${n === 1 ? "" : "s"}`;

/** Self-service password change: current + new + confirmation → POST /api/account/password. */
export function ChangePasswordForm({ minLength, upn }: ChangePasswordFormProps) {
  const router = useRouter();
  const [currentPassword, setCurrent] = useState("");
  const [newPassword, setNew] = useState("");
  const [confirmPassword, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);

  const mismatch = confirmPassword.length > 0 && confirmPassword !== newPassword;

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setDone(null);
    if (newPassword !== confirmPassword) {
      setError("The new password and its confirmation do not match.");
      return;
    }
    setBusy(true);
    const r = await callApi<RevokeResult>("/api/account/password", "POST", { currentPassword, newPassword, confirmPassword });
    setBusy(false);
    if (!r.ok) {
      setError(r.error);
      if (SIGNED_OUT.test(r.error)) window.setTimeout(() => router.push("/login"), 2500);
      return;
    }
    setCurrent("");
    setNew("");
    setConfirm("");
    setDone(`Password changed.${r.data.revokedSessions > 0 ? ` Signed out ${plural(r.data.revokedSessions)}.` : ""}`);
  }

  return (
    <form method="post" onSubmit={submit} className="max-w-md space-y-4">
      {error && <Alert tone="bad">{error}</Alert>}
      {done && <Alert tone="good">{done}</Alert>}
      {/* Lets password managers associate the new password with the right account. */}
      <input type="text" name="username" autoComplete="username" value={upn} readOnly hidden />
      <label className={labelCls}>
        Current password
        <input
          className={inputCls}
          name="currentPassword"
          type="password"
          autoComplete="current-password"
          required
          maxLength={1024}
          value={currentPassword}
          onChange={(e) => setCurrent(e.target.value)}
        />
      </label>
      <label className={labelCls}>
        New password
        <input
          className={inputCls}
          name="newPassword"
          type="password"
          autoComplete="new-password"
          required
          minLength={minLength}
          maxLength={1024}
          value={newPassword}
          onChange={(e) => setNew(e.target.value)}
        />
      </label>
      <label className={labelCls}>
        Confirm new password
        <input
          className={inputCls}
          name="confirmPassword"
          type="password"
          autoComplete="new-password"
          required
          minLength={minLength}
          maxLength={1024}
          aria-invalid={mismatch}
          value={confirmPassword}
          onChange={(e) => setConfirm(e.target.value)}
        />
        {mismatch && <span className="mt-1 block text-xs text-danger">Does not match the new password.</span>}
      </label>
      <button type="submit" disabled={busy || mismatch} className={`${buttonBase} ${BUTTON.primary}`}>
        {busy ? <Loader2 size={16} className="animate-spin" aria-hidden /> : <KeyRound size={16} aria-hidden />}
        {busy ? "Changing…" : "Change password"}
      </button>
    </form>
  );
}

/** "Sign out of all other sessions" → POST /api/account/sessions/revoke-others, then re-render the list. */
export function RevokeOthersButton({ disabled }: { disabled: boolean }) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ tone: "good" | "bad"; text: string } | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setMessage(null);
    const r = await callApi<RevokeResult>("/api/account/sessions/revoke-others", "POST");
    setBusy(false);
    if (!r.ok) {
      setMessage({ tone: "bad", text: r.error });
      return;
    }
    setMessage({ tone: "good", text: `Signed out ${plural(r.data.revokedSessions)}.` });
    router.refresh();
  }

  return (
    <form method="post" onSubmit={submit} className="flex items-center gap-3">
      {message && <span className={`text-xs ${message.tone === "good" ? "text-success" : "text-danger"}`}>{message.text}</span>}
      <button type="submit" disabled={busy || disabled} className={`${buttonBase} ${BUTTON.default}`}>
        {busy ? <Loader2 size={16} className="animate-spin" aria-hidden /> : <LogOut size={16} aria-hidden />}
        Sign out of all other sessions
      </button>
    </form>
  );
}
