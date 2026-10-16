"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { Loader2 } from "lucide-react";
import { callApi } from "./api-client";
import { BUTTON, buttonBase } from "./ui";

interface ActionButtonProps {
  url: string;
  label: string;
  method?: "POST" | "PATCH";
  body?: unknown;
  /** Ask for confirmation first (irreversible actions) */
  confirmText?: string;
  /** Prompt for a reason (e.g. reject) and send it as { reason } */
  askReason?: boolean;
  variant?: keyof typeof BUTTON;
  icon?: React.ReactNode;
}

export function ActionButton({ url, label, method = "POST", body, confirmText, askReason, variant = "default", icon }: ActionButtonProps) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function run() {
    setError(null);
    let payload = body;
    if (askReason) {
      const reason = window.prompt(`${label}: reason`);
      if (reason === null) return;
      payload = { ...(typeof body === "object" && body ? body : {}), reason };
    } else if (confirmText && !window.confirm(confirmText)) {
      return;
    }
    setBusy(true);
    const r = await callApi(url, method, payload ?? {});
    setBusy(false);
    if (!r.ok) {
      setError(r.error);
      return;
    }
    startTransition(() => router.refresh());
  }

  const working = busy || pending;
  return (
    <span className="inline-flex flex-col items-start gap-1">
      <button type="button" onClick={run} disabled={working} className={`${buttonBase} ${BUTTON[variant]}`}>
        {working ? <Loader2 size={15} className="animate-spin" /> : icon}
        {working ? "Working…" : label}
      </button>
      {error && (
        <span role="alert" className="max-w-xs text-xs text-danger">
          {error}
        </span>
      )}
    </span>
  );
}
