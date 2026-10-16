"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { Loader2, Plus } from "lucide-react";
import { callApi } from "@/components/api-client";
import { BUTTON, buttonBase, inputCls, labelCls } from "@/components/ui";

interface EventToggle {
  event: string;
  label: string;
  severity?: string;
  enabled: boolean;
}

function useAction() {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);
  async function run(url: string, body: unknown, okText: string): Promise<boolean> {
    setError(null);
    setDone(null);
    setBusy(true);
    const r = await callApi(url, "POST", body);
    setBusy(false);
    if (!r.ok) {
      setError(r.error);
      return false;
    }
    setDone(okText);
    startTransition(() => router.refresh());
    return true;
  }
  return { run, working: busy || pending, error, done };
}

function Feedback({ error, done }: { error: string | null; done: string | null }) {
  if (error) return <p role="alert" className="text-sm text-danger">{error}</p>;
  if (done) return <p role="status" className="text-sm text-success">{done}</p>;
  return null;
}

/** Add a Teams / Slack incoming-webhook URL to one scope. */
export function AddWebhookForm({ scope, hosts }: { scope: string; hosts: string[] }) {
  const [url, setUrl] = useState("");
  const { run, working, error, done } = useAction();
  const disabled = hosts.length === 0;
  return (
    <form
      className="space-y-2"
      onSubmit={async (e) => {
        e.preventDefault();
        if (await run("/api/notifications/settings", { scope, action: "add-webhook", url }, "Webhook added")) setUrl("");
      }}
    >
      <label className={labelCls} htmlFor={`wh-${scope}`}>
        Add webhook URL
      </label>
      <div className="flex flex-wrap gap-2">
        <input
          id={`wh-${scope}`}
          type="url"
          required
          disabled={disabled}
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://…"
          autoComplete="off"
          className={`${inputCls} mt-0 min-w-0 flex-1`}
        />
        <button type="submit" disabled={working || disabled} className={`${buttonBase} ${BUTTON.primary}`}>
          {working ? <Loader2 size={15} className="animate-spin" /> : <Plus size={15} />}
          Add
        </button>
      </div>
      <p className="text-xs text-muted">
        {disabled
          ? "Webhooks are disabled until the platform operator allow-lists webhook hosts (NOTIFY_WEBHOOK_ALLOWED_HOSTS)."
          : `HTTPS only. Allowed hosts: ${hosts.join(", ")}. The URL is stored server-side and only shown masked.`}
      </p>
      <Feedback error={error} done={done} />
    </form>
  );
}

/** Event switches for a scope (bank / platform settings). */
export function EventTogglesForm({ scope, events }: { scope: string; events: EventToggle[] }) {
  const [state, setState] = useState<Record<string, boolean>>(() => Object.fromEntries(events.map((e) => [e.event, e.enabled])));
  const { run, working, error, done } = useAction();
  return (
    <form
      className="space-y-3"
      onSubmit={async (e) => {
        e.preventDefault();
        const disabledEvents = Object.entries(state).filter(([, on]) => !on).map(([k]) => k);
        await run("/api/notifications/settings", { scope, action: "set-events", disabledEvents }, "Saved");
      }}
    >
      <fieldset className="grid gap-2 sm:grid-cols-2">
        <legend className="sr-only">Events</legend>
        {events.map((e) => (
          <label key={e.event} className="flex items-start gap-2 text-sm text-fg">
            <input
              type="checkbox"
              className="mt-0.5"
              checked={state[e.event] ?? true}
              onChange={(ev) => setState((s) => ({ ...s, [e.event]: ev.target.checked }))}
            />
            <span>{e.label}</span>
          </label>
        ))}
      </fieldset>
      <p className="text-xs text-muted">Critical events (audit-chain / SIEM integrity, account security) are always delivered and are not listed.</p>
      <div className="flex items-center gap-3">
        <button type="submit" disabled={working} className={`${buttonBase} ${BUTTON.primary}`}>
          {working && <Loader2 size={15} className="animate-spin" />}
          Save event settings
        </button>
        <Feedback error={error} done={done} />
      </div>
    </form>
  );
}

/** Personal opt-outs (each switch saves immediately). */
export function OptOutToggles({ items }: { items: { event: string; label: string; optedOut: boolean }[] }) {
  const { run, working, error, done } = useAction();
  if (items.length === 0) return <p className="text-sm text-muted">No optional notifications for your role.</p>;
  return (
    <div className="space-y-3">
      <div className="grid gap-2 sm:grid-cols-2">
        {items.map((i) => (
          <label key={i.event} className="flex items-start gap-2 text-sm text-fg">
            <input
              type="checkbox"
              className="mt-0.5"
              disabled={working}
              defaultChecked={!i.optedOut}
              onChange={(ev) => void run("/api/notifications/opt-outs", { event: i.event, optedOut: !ev.target.checked }, "Saved")}
            />
            <span>{i.label}</span>
          </label>
        ))}
      </div>
      <Feedback error={error} done={done} />
    </div>
  );
}
