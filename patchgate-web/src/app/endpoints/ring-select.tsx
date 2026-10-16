"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { callApi } from "@/components/api-client";

interface Props {
  endpointId: string;
  ringId: string | null;
  rings: { id: string; name: string }[];
  disabled: boolean;
}

export function RingSelect({ endpointId, ringId, rings, disabled }: Props) {
  const router = useRouter();
  const [value, setValue] = useState(ringId ?? "");
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  async function change(next: string) {
    const prev = value;
    setValue(next);
    setError(null);
    const r = await callApi(`/api/endpoints/${endpointId}`, "PATCH", { ringId: next || null });
    if (!r.ok) {
      setValue(prev);
      setError(r.error);
      return;
    }
    startTransition(() => router.refresh());
  }

  return (
    <span className="inline-flex flex-col">
      <select
        aria-label="Ring"
        value={value}
        disabled={disabled || pending}
        onChange={(e) => change(e.target.value)}
        className={`rounded-lg border bg-surface px-2.5 py-1.5 text-sm text-fg shadow-sm focus:border-primary focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-60 ${value ? "border-border-strong" : "border-warning/60 text-warning"}`}
      >
        <option value="">— unassigned —</option>
        {rings.map((r) => (
          <option key={r.id} value={r.id}>{r.name}</option>
        ))}
      </select>
      {error && <span role="alert" className="text-xs text-danger">{error}</span>}
    </span>
  );
}
