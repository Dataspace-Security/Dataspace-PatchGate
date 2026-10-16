"use client";

import { useState } from "react";
import { CheckCircle2, SearchCheck, XCircle } from "lucide-react";
import { callApi } from "@/components/api-client";
import { BUTTON, buttonBase, inputCls, labelCls } from "@/components/ui";

/** Auditor pastes seq + hash from an ANCHOR record found in the SIEM (checked against the chain shown). */
export function VerifyAnchorForm({ platformChain = false }: { platformChain?: boolean }) {
  const [seq, setSeq] = useState("");
  const [hash, setHash] = useState("");
  const [result, setResult] = useState<{ match: boolean; reason: string | null } | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setResult(null);
    const r = await callApi<{ match: boolean; reason: string | null }>("/api/audit/verify", "POST", {
      seq: seq.trim(),
      hash: hash.trim().toLowerCase(),
      ...(platformChain ? { chain: "platform" } : {}),
    });
    if (!r.ok) return setError(r.error);
    setResult(r.data);
  }

  return (
    <form method="post" onSubmit={submit} className="space-y-4">
      <div className="grid gap-4 md:grid-cols-[180px_1fr]">
        <label className={labelCls}>
          seq
          <input className={`${inputCls} font-mono`} value={seq} onChange={(e) => setSeq(e.target.value)} required pattern="\d+" placeholder="1042" />
        </label>
        <label className={labelCls}>
          hash
          <input className={`${inputCls} font-mono`} value={hash} onChange={(e) => setHash(e.target.value)} required pattern="[a-fA-F0-9]{64}" placeholder="64 hex characters" />
        </label>
      </div>
      <button type="submit" className={`${buttonBase} ${BUTTON.default}`}>
        <SearchCheck size={15} /> Check against PatchGate DB
      </button>
      {error && <p role="alert" className="rounded-lg bg-danger-soft px-3 py-2 text-sm text-danger">{error}</p>}
      {result && (
        <p role="status" className={`flex items-center gap-2 rounded-lg px-3 py-2 text-sm font-medium ${result.match ? "bg-success-soft text-success" : "bg-danger-soft text-danger"}`}>
          {result.match ? <CheckCircle2 size={16} /> : <XCircle size={16} />}
          {result.match ? "Matches — no tampering up to this point." : result.reason}
        </p>
      )}
    </form>
  );
}
