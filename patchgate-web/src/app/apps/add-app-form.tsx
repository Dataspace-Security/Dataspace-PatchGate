"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Loader2, Plus } from "lucide-react";
import { callApi } from "@/components/api-client";
import { BUTTON, buttonBase, inputCls, labelCls } from "@/components/ui";

const EMPTY = { wingetId: "", displayName: "", inventoryMatch: "", expectedPublisher: "", allowedDomains: "", strictHosts: false, allowHashDrift: false };

export function AddAppForm() {
  const router = useRouter();
  const [f, setF] = useState(EMPTY);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const set = (k: "wingetId" | "displayName" | "inventoryMatch" | "expectedPublisher" | "allowedDomains") => (e: React.ChangeEvent<HTMLInputElement>) =>
    setF({ ...f, [k]: e.target.value });
  const toggle = (k: "strictHosts" | "allowHashDrift") => (e: React.ChangeEvent<HTMLInputElement>) => setF({ ...f, [k]: e.target.checked });

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    const r = await callApi("/api/apps", "POST", {
      ...f,
      expectedPublisher: f.expectedPublisher.trim() || null,
      allowedDomains: f.allowedDomains.split(",").map((d) => d.trim()).filter(Boolean),
    });
    setBusy(false);
    if (!r.ok) return setError(r.error);
    setF(EMPTY);
    router.refresh();
  }

  return (
    <form method="post" onSubmit={submit} className="grid gap-4 md:grid-cols-2">
      <p className="text-sm text-muted md:col-span-2">
        Tip: apps already installed on your PCs appear on the <a href="/discovery" className="font-medium text-primary underline-offset-2 hover:underline">Discovery</a> page and can be managed in one click.
      </p>
      <label className={labelCls}>
        winget ID
        <input className={inputCls} placeholder="Microsoft.PowerShell" value={f.wingetId} onChange={set("wingetId")} required />
      </label>
      <label className={labelCls}>
        Display name
        <input className={inputCls} placeholder="PowerShell 7" value={f.displayName} onChange={set("displayName")} required />
      </label>
      <label className={labelCls}>
        Inventory match <span className="font-normal text-muted">(regex on installed-software name)</span>
        <input className={inputCls} placeholder="^PowerShell 7" value={f.inventoryMatch} onChange={set("inventoryMatch")} required />
      </label>
      <label className={labelCls}>
        Pinned signer <span className="font-normal text-muted">(optional — empty: first download is held for you to approve)</span>
        <input className={inputCls} placeholder="O=Microsoft Corporation" value={f.expectedPublisher} onChange={set("expectedPublisher")} />
      </label>
      <label className={`${labelCls} md:col-span-2`}>
        Download hosts <span className="font-normal text-muted">(optional, comma-separated — empty: the vendor host named in the winget manifest)</span>
        <input className={inputCls} placeholder="github.com" value={f.allowedDomains} onChange={set("allowedDomains")} />
      </label>
      <label className="flex items-start gap-2 text-sm">
        <input type="checkbox" className="mt-0.5 size-4 accent-[var(--primary)]" checked={f.strictHosts} onChange={toggle("strictHosts")} />
        <span>
          <span className="font-medium">Strict hosts</span>
          <span className="block text-muted">Every redirect must stay on the hosts above. Off: vendor mirror networks are followed (the file is still hash- and signer-checked).</span>
        </span>
      </label>
      <label className="flex items-start gap-2 text-sm">
        <input type="checkbox" className="mt-0.5 size-4 accent-[var(--primary)]" checked={f.allowHashDrift} onChange={toggle("allowHashDrift")} />
        <span>
          <span className="font-medium">Rolling vendor URL</span>
          <span className="block text-muted">For vendors whose download link always serves the newest build (e.g. Chrome): a hash mismatch from the pinned signer is held for approval instead of rejected.</span>
        </span>
      </label>
      {error && <p role="alert" className="rounded-lg bg-danger-soft px-3 py-2 text-sm text-danger md:col-span-2">{error}</p>}
      <div className="md:col-span-2">
        <button type="submit" disabled={busy} className={`${buttonBase} ${BUTTON.primary}`}>
          {busy ? <Loader2 size={15} className="animate-spin" /> : <Plus size={15} />}
          {busy ? "Adding…" : "Add to allow-list"}
        </button>
      </div>
    </form>
  );
}
