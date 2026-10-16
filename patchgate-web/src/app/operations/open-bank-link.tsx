"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { Loader2 } from "lucide-react";
import { callApi } from "@/components/api-client";

interface OpenBankLinkProps {
  tenantId: string;
  href: string;
  label: string;
  className?: string;
}

/**
 * Drill-down into a bank page: switches the acting bank first (audited vendor access, like the sidebar
 * switcher), then opens the page.
 */
export function OpenBankLink({ tenantId, href, label, className }: OpenBankLinkProps) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  async function open() {
    setBusy(true);
    setError(null);
    const r = await callApi("/api/tenant/select", "POST", { tenantId });
    setBusy(false);
    if (!r.ok) {
      setError(r.error);
      return;
    }
    startTransition(() => router.push(href));
  }

  return (
    <span className="inline-flex items-center gap-1">
      <button
        type="button"
        onClick={() => void open()}
        disabled={busy || pending}
        title={error ?? `Act for this bank and open ${href}`}
        className={className ?? "text-left text-primary hover:underline disabled:opacity-60"}
      >
        {label}
      </button>
      {(busy || pending) && <Loader2 size={12} className="animate-spin text-muted" aria-hidden />}
      {error && <span className="text-xs text-danger">{error}</span>}
    </span>
  );
}
