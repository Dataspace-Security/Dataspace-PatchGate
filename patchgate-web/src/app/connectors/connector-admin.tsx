"use client";

import { useState, useTransition, type FormEvent } from "react";
import { useRouter } from "next/navigation";
import { Check, Copy, KeyRound, Loader2, Pencil } from "lucide-react";
import { callApi } from "@/components/api-client";
import { Alert, BUTTON, Card, buttonBase, inputCls, labelCls } from "@/components/ui";

interface CreatedCode {
  code: string;
  name: string;
  expiresAt: string;
  serverUrl: string;
  initCommand: string;
  fingerprint: string;
  siteInstallCommand: string;
  usbInstallCommand: string;
  bundleVersion: string | null;
}

function CommandBlock({ label, command, copyLabel }: { label: string; command: string; copyLabel: string }) {
  return (
    <div>
      <div className="mb-1 flex items-center justify-between gap-2">
        <span className={labelCls}>{label}</span>
        <CopyButton text={command} label={copyLabel} />
      </div>
      <pre className="overflow-x-auto whitespace-pre-wrap break-all rounded-lg border border-border bg-surface-2 p-3 font-mono text-xs leading-relaxed text-fg">{command}</pre>
    </div>
  );
}

const utc = (iso: string) => `${new Date(iso).toISOString().replace("T", " ").slice(0, 16)} UTC`;

function CopyButton({ text, label }: { text: string; label: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      onClick={() => {
        void navigator.clipboard?.writeText(text).then(() => {
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        });
      }}
      className={`${buttonBase} ${BUTTON.default} px-2.5 py-1.5 text-xs`}
    >
      {copied ? <Check size={13} aria-hidden /> : <Copy size={13} aria-hidden />}
      {copied ? "Copied" : label}
    </button>
  );
}

/** Platform admins: one-time enrolment code for a bank site (shown once, valid 24 h, single use). */
export function CreateEnrollmentForm({ banks }: { banks: { id: string; name: string }[] }) {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [tenantId, setTenantId] = useState(banks[0]?.id ?? "");
  const [name, setName] = useState("");
  const [created, setCreated] = useState<CreatedCode | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    const r = await callApi<CreatedCode>("/api/connector/admin/enrollments", "POST", { tenantId, name });
    setBusy(false);
    if (!r.ok) return setError(r.error);
    setCreated(r.data);
    setName("");
    router.refresh();
  }

  if (created) {
    return (
      <Card title={`Enrolment code for “${created.name}”`} description="Shown only once. Valid for 24 hours and for a single connector.">
        <div className="space-y-4">
          <div className="flex flex-wrap items-center gap-3">
            <code className="rounded-lg border border-border-strong bg-surface-2 px-4 py-2 font-mono text-lg tracking-widest text-fg">{created.code}</code>
            <CopyButton text={created.code} label="Copy code" />
          </div>
          <div className="space-y-2">
            <CommandBlock label="Step 1 (bank IT, on the new site VM): one-line install of the whole site" command={created.siteInstallCommand} copyLabel="Copy command" />
            <p className="text-xs text-muted">
              VM with internet access: add <code className="font-mono">--online</code> (downloads the small online bundle; public images are pulled by digest).
              {created.bundleVersion ? ` Site bundle ${created.bundleVersion}.` : " Site bundles are not configured on this platform yet (PATCHGATE_SITE_BUNDLE_DIR): use the USB alternative."}
            </p>
          </div>
          <div>
            <div className="mb-1 flex items-center justify-between gap-2">
              <span className={labelCls}>Confirm the fingerprint by phone (job-signing key, SHA-256)</span>
              <CopyButton text={created.fingerprint} label="Copy fingerprint" />
            </div>
            <code className="block break-all rounded-lg border border-border bg-surface-2 p-3 font-mono text-xs text-fg">{created.fingerprint}</code>
            <p className="mt-1 text-xs text-muted">
              Send the command (with the code) and the fingerprint over two different channels; the bank reads the fingerprint back on the phone. The site pins it and refuses any other job key.
            </p>
            <p className="mt-2 text-xs text-muted">
              Code valid until {utc(created.expiresAt)} (single use). The connector generates its own key; the private key never leaves the bank.
            </p>
          </div>
          <details className="rounded-lg border border-border p-3">
            <summary className="cursor-pointer text-sm font-medium text-fg">Offline / USB alternative and manual connector init</summary>
            <div className="mt-3 space-y-3">
              <p className="text-xs text-muted">
                Copy <code className="font-mono">patchgate-site-{created.bundleVersion ?? "<version>"}.tar.gz</code> and <code className="font-mono">SHA256SUMS</code> (from the platform&apos;s site-bundle release) onto the VM, next to <code className="font-mono">install-site.sh</code>, then run:
              </p>
              <CommandBlock label="USB install" command={created.usbInstallCommand} copyLabel="Copy USB command" />
              <CommandBlock label="Connector only (existing Tactical host)" command={created.initCommand} copyLabel="Copy init command" />
            </div>
          </details>
          <button type="button" onClick={() => setCreated(null)} className={`${buttonBase} ${BUTTON.default}`}>
            Done
          </button>
        </div>
      </Card>
    );
  }

  if (!open) {
    return (
      <button type="button" onClick={() => setOpen(true)} disabled={banks.length === 0} className={`${buttonBase} ${BUTTON.primary}`}>
        <KeyRound size={16} aria-hidden /> Enrol a site connector
      </button>
    );
  }

  return (
    <Card title="Enrol a site connector" description="Creates a one-time code for one bank site. Re-using an existing site name re-keys that site's connector.">
      <form method="post" onSubmit={submit} className="grid gap-4 md:grid-cols-2">
        <label className={labelCls}>
          Bank
          <select className={inputCls} value={tenantId} onChange={(e) => setTenantId(e.target.value)} required>
            {banks.map((b) => (
              <option key={b.id} value={b.id}>
                {b.name}
              </option>
            ))}
          </select>
        </label>
        <label className={labelCls}>
          Site name
          <input
            className={inputCls}
            required
            minLength={2}
            maxLength={80}
            pattern="[A-Za-z0-9][A-Za-z0-9 .,\(\)_\/\-]*"
            placeholder="Head office DC"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
        </label>
        {error && (
          <div className="md:col-span-2">
            <Alert tone="bad">{error}</Alert>
          </div>
        )}
        <div className="flex gap-2 md:col-span-2">
          <button type="submit" disabled={busy || !tenantId} className={`${buttonBase} ${BUTTON.primary}`}>
            {busy && <Loader2 size={15} className="animate-spin" aria-hidden />}
            Create code
          </button>
          <button type="button" onClick={() => setOpen(false)} className={`${buttonBase} ${BUTTON.default}`}>
            Cancel
          </button>
        </div>
      </form>
    </Card>
  );
}

/** Platform admins: edit a connector's LAN limits inline. */
export function LimitsEditor({ id, maxConcurrentInstalls, bandwidthLimitMbps }: { id: string; maxConcurrentInstalls: number; bandwidthLimitMbps: number | null }) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [editing, setEditing] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [installs, setInstalls] = useState(String(maxConcurrentInstalls));
  const [mbps, setMbps] = useState(bandwidthLimitMbps === null ? "" : String(bandwidthLimitMbps));
  const small = "px-2.5 py-1.5 text-xs";

  async function save(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    const r = await callApi(`/api/connector/admin/connectors/${encodeURIComponent(id)}`, "PATCH", {
      maxConcurrentInstalls: Number(installs),
      bandwidthLimitMbps: mbps.trim() === "" ? null : Number(mbps),
    });
    setBusy(false);
    if (!r.ok) return setError(r.error);
    setEditing(false);
    startTransition(() => router.refresh());
  }

  if (!editing) {
    return (
      <button type="button" onClick={() => setEditing(true)} className={`${buttonBase} ${BUTTON.default} ${small}`}>
        <Pencil size={13} aria-hidden /> Limits
      </button>
    );
  }
  return (
    <form method="post" onSubmit={save} className="flex flex-col items-end gap-2 text-left">
      <label className="text-xs text-muted">
        Max concurrent installs
        <input className={`${inputCls} w-28`} type="number" min={1} max={1000} required value={installs} onChange={(e) => setInstalls(e.target.value)} />
      </label>
      <label className="text-xs text-muted">
        Cache bandwidth (Mbit/s, empty = no cap)
        <input className={`${inputCls} w-28`} type="number" min={1} max={100000} value={mbps} onChange={(e) => setMbps(e.target.value)} />
      </label>
      {error && (
        <span role="alert" className="max-w-xs text-xs text-danger">
          {error}
        </span>
      )}
      <div className="flex gap-1.5">
        <button type="submit" disabled={busy || pending} className={`${buttonBase} ${BUTTON.primary} ${small}`}>
          {(busy || pending) && <Loader2 size={13} className="animate-spin" aria-hidden />}
          Save
        </button>
        <button type="button" onClick={() => setEditing(false)} className={`${buttonBase} ${BUTTON.default} ${small}`}>
          Cancel
        </button>
      </div>
    </form>
  );
}
