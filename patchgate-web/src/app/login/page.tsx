import { Suspense } from "react";
import Link from "next/link";
import { connection } from "next/server";
import { LogIn, ShieldCheck } from "lucide-react";
import { authMode } from "@/lib/env";
import { safeReturnTo } from "@/lib/auth/claims";
import { Alert, BUTTON, Loading, buttonBase } from "@/components/ui";
import { LocalLoginForm } from "./local-login-form";

const MESSAGES: Record<string, { tone: "bad" | "warn" | "info" | "good"; text: string }> = {
  denied: { tone: "bad", text: "Your directory account is not assigned a PatchGate role, or it has been deactivated. Ask the PatchGate administrator." },
  deactivated: { tone: "bad", text: "Your account has been deactivated. Ask your PatchGate administrator." },
  expired: { tone: "warn", text: "Your session expired. Please sign in again." },
  failed: { tone: "bad", text: "Sign-in could not be completed. Please try again; if it keeps failing, contact the service desk." },
  unavailable: { tone: "bad", text: "The bank identity provider is not reachable right now." },
  signin: { tone: "info", text: "Please sign in to continue." },
};

async function LoginCard({ searchParams }: { searchParams: PageProps<"/login">["searchParams"] }) {
  await connection();
  const sp = await searchParams;
  const one = (v: string | string[] | undefined) => (Array.isArray(v) ? v[0] : v);
  const error = one(sp.error);
  const returnTo = safeReturnTo(one(sp.returnTo));
  const msg = error ? MESSAGES[error] : one(sp.signedOut) ? { tone: "good" as const, text: "You have been signed out." } : null;
  const mode = authMode();

  return (
    <div className="mx-auto mt-10 max-w-md space-y-5 rounded-2xl border border-border bg-surface p-8 shadow-card">
      <div className="flex items-center gap-3">
        <span className="flex h-11 w-11 items-center justify-center rounded-xl bg-gradient-to-br from-primary to-accent text-white">
          <ShieldCheck size={22} />
        </span>
        <div>
          <h1 className="text-lg font-semibold">Sign in to PatchGate</h1>
          <p className="text-sm text-muted">Approval-gated patching for your bank</p>
        </div>
      </div>
      {msg && <Alert tone={msg.tone}>{msg.text}</Alert>}
      {mode === "local" ? (
        <LocalLoginForm returnTo={returnTo} />
      ) : mode === "oidc" ? (
        <a href={`/api/auth/login?returnTo=${encodeURIComponent(returnTo)}`} className={`${buttonBase} ${BUTTON.primary} w-full justify-center`}>
          <LogIn size={16} /> Sign in with bank SSO
        </a>
      ) : (
        <Link href="/dev-login" className={`${buttonBase} ${BUTTON.default} w-full justify-center`}>
          Development sign-in
        </Link>
      )}
      <p className="border-t border-border pt-4 text-xs text-muted">All sign-ins, denials and sign-outs are recorded in the tamper-evident audit log and exported to the bank SIEM.</p>
    </div>
  );
}

export default function LoginPage({ searchParams }: PageProps<"/login">) {
  return (
    <Suspense fallback={<Loading />}>
      <LoginCard searchParams={searchParams} />
    </Suspense>
  );
}
