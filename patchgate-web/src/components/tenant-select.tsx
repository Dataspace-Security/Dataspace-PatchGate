"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { Loader2 } from "lucide-react";
import { callApi } from "./api-client";

export interface TenantOption {
  id: string;
  name: string;
}

interface TenantSelectProps {
  tenants: readonly TenantOption[];
  activeId: string | null;
  /** "sidebar" = dark sidebar/top bar; "page" = the bank picker page */
  variant?: "sidebar" | "page";
}

/** Bank switcher for platform staff. The server re-validates the choice on every request. */
export function TenantSelect({ tenants, activeId, variant = "sidebar" }: TenantSelectProps) {
  const router = useRouter();
  const [value, setValue] = useState(activeId ?? "");
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();
  const [busy, setBusy] = useState(false);

  async function change(next: string) {
    const prev = value;
    setValue(next);
    setError(null);
    setBusy(true);
    const r = await callApi("/api/tenant/select", "POST", { tenantId: next || null });
    setBusy(false);
    if (!r.ok) {
      setValue(prev);
      setError(r.error);
      return;
    }
    startTransition(() => {
      if (variant === "page" && next) router.push("/");
      router.refresh();
    });
  }

  const cls =
    variant === "sidebar"
      ? "w-full rounded-lg border border-white/10 bg-sidebar-active px-2.5 py-1.5 text-sm text-white focus:outline-none focus:ring-2 focus:ring-accent"
      : "w-full rounded-lg border border-border bg-surface px-3 py-2 text-sm text-fg focus:outline-none focus:ring-2 focus:ring-primary";

  return (
    <div className="space-y-1">
      <div className="flex items-center gap-2">
        <select
          aria-label="Acting for bank"
          className={cls}
          value={value}
          disabled={busy || pending}
          onChange={(e) => void change(e.target.value)}
        >
          <option value="">— Select a bank —</option>
          {tenants.map((t) => (
            <option key={t.id} value={t.id}>
              {t.name}
            </option>
          ))}
        </select>
        {(busy || pending) && <Loader2 size={15} className="shrink-0 animate-spin text-sidebar-fg" aria-hidden />}
      </div>
      {error && (
        <p role="alert" className="text-xs text-danger">
          {error}
        </p>
      )}
    </div>
  );
}
