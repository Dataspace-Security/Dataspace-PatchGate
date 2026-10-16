import { lookup as dnsLookup } from "node:dns/promises";
import { isIP } from "node:net";
import { assertAllowedUrl, isNonPublic } from "@/lib/fetch/http";

/**
 * SSRF-safe webhook delivery (Teams / Slack incoming webhooks).
 *  - https only, default port, no credentials, no IP literals, host must be on the platform admin's
 *    allow-list (NOTIFY_WEBHOOK_ALLOWED_HOSTS, exact names — no suffix matching);
 *  - the host must resolve to PUBLIC addresses only (no requests into the bank / our private network);
 *  - redirects are never followed (a 3xx is a delivery error), bounded timeout, response body discarded.
 * Residual risk (as for the fetcher): DNS could change between the check and the connection; the egress
 * firewall allow-list remains the primary control.
 */

export type Lookup = (host: string) => Promise<{ address: string }[]>;

export interface WebhookDeps {
  allowedHosts: readonly string[];
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
  lookup?: Lookup;
}

export type WebhookResult = { ok: true; status: number } | { ok: false; permanent: boolean; error: string };

const DEFAULT_TIMEOUT_MS = 10_000;
const MAX_URL_LENGTH = 2_000;
const HOST_RE = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

const defaultLookup: Lookup = (host) => dnsLookup(host, { all: true, verbatim: true });

/** Parse NOTIFY_WEBHOOK_ALLOWED_HOSTS ("a.example.com, b.example.com"): DNS names only, lower-case, unique. */
export function parseAllowedHosts(raw: string | undefined | null): string[] {
  if (!raw) return [];
  const out = new Set<string>();
  for (const part of raw.split(/[\s,;]+/)) {
    const h = part.trim().toLowerCase().replace(/\.$/, "");
    if (h && isIP(h) === 0 && HOST_RE.test(h)) out.add(h);
  }
  return [...out];
}

/** Validate a webhook URL for storage (settings) — same rules as delivery, minus DNS. Returns the normalised URL. */
export function validateWebhookUrl(raw: string, allowedHosts: readonly string[]): string {
  const v = raw.trim();
  if (v.length > MAX_URL_LENGTH) throw new Error("Webhook URL is too long");
  if (allowedHosts.length === 0) throw new Error("Webhooks are disabled: the platform has not allow-listed any webhook host (NOTIFY_WEBHOOK_ALLOWED_HOSTS)");
  const u = assertAllowedUrl(v, allowedHosts);
  u.hash = "";
  return u.toString();
}

/** Display form: host + the last 4 characters (incoming-webhook URLs embed a secret token in the path). */
export function maskWebhookUrl(raw: string): string {
  try {
    const u = new URL(raw);
    const tail = (u.pathname + u.search).slice(-4);
    return `https://${u.hostname}/…${tail}`;
  } catch {
    return "(invalid URL)";
  }
}

async function assertPublic(host: string, lookup: Lookup): Promise<void> {
  const addrs = await lookup(host);
  if (addrs.length === 0) throw new Error(`Host ${host} did not resolve`);
  for (const { address } of addrs) {
    if (isNonPublic(address)) throw new Error(`Host ${host} resolves to a non-public address`);
  }
}

function errText(err: unknown): string {
  if (err instanceof Error) return err.name === "TimeoutError" || err.name === "AbortError" ? "timed out" : err.message;
  return "unknown error";
}

/** POST one JSON payload. Never throws; `permanent` errors are not retried (bad URL, 4xx except 408/429). */
export async function postWebhook(url: string, payload: unknown, deps: WebhookDeps): Promise<WebhookResult> {
  let target: URL;
  try {
    target = assertAllowedUrl(url, deps.allowedHosts);
  } catch (err: unknown) {
    return { ok: false, permanent: true, error: `webhook URL refused: ${errText(err)}` };
  }
  try {
    await assertPublic(target.hostname, deps.lookup ?? defaultLookup);
  } catch (err: unknown) {
    const msg = errText(err);
    return { ok: false, permanent: /non-public/.test(msg), error: msg };
  }
  const doFetch = deps.fetchImpl ?? fetch;
  try {
    const res = await doFetch(target.toString(), {
      method: "POST",
      redirect: "manual",
      headers: { "Content-Type": "application/json", "User-Agent": "Dataspace-PatchGate" },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(deps.timeoutMs ?? DEFAULT_TIMEOUT_MS),
    });
    await res.body?.cancel().catch(() => undefined);
    if (res.status >= 200 && res.status < 300) return { ok: true, status: res.status };
    if (res.status >= 300 && res.status < 400) return { ok: false, permanent: true, error: `HTTP ${res.status}: redirects are not followed` };
    const permanent = res.status >= 400 && res.status < 500 && res.status !== 408 && res.status !== 429;
    return { ok: false, permanent, error: `HTTP ${res.status} from ${target.hostname}` };
  } catch (err: unknown) {
    return { ok: false, permanent: false, error: errText(err) };
  }
}
