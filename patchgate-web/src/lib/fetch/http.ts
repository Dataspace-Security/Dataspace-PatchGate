import { createHash } from "node:crypto";
import { lookup as dnsLookup } from "node:dns/promises";
import { createWriteStream } from "node:fs";
import { rm } from "node:fs/promises";
import { BlockList, isIP } from "node:net";

/**
 * The ONLY code in PatchGate that talks to the internet.
 * - https only, default port only, exact host allow-list (no suffix matching), no IP literals
 * - every hop's hostname must resolve to PUBLIC addresses only (no SSRF into the bank network)
 * - redirects followed manually, each hop re-checked, max 5 hops, redirect bodies released
 * - credentials (e.g. GitHub token) sent only to their own host, never to redirect targets
 * - text responses and downloads are streamed with byte caps; downloads hashed on the fly
 * Residual risk: DNS can change between this check and the connection (rebinding); the egress
 * firewall allow-list remains the primary control.
 */

const MAX_REDIRECTS = 5;
const DEFAULT_MAX_TEXT_BYTES = 5_000_000;

type Lookup = (host: string) => Promise<{ address: string }[]>;

export interface FetchOpts {
  allowedHosts: readonly string[];
  timeoutMs: number;
  /** Headers sent ONLY to `host` (exact match), e.g. GitHub API token */
  authHeaders?: { host: string; headers: Record<string, string> };
  maxTextBytes?: number;
  /**
   * "allowlist" (default): every hop must be allow-listed.
   * "public": the FIRST hop must be allow-listed; redirects may go to any public https host. Only for
   * downloads whose bytes are verified independently (catalog SHA-256 + Authenticode pin), e.g. vendor
   * mirror networks (VLC). SSRF guards (https, no IP literals, public DNS only) still apply to every hop.
   */
  redirects?: "allowlist" | "public";
  fetchImpl?: typeof fetch;
  lookup?: Lookup;
}

const NON_PUBLIC = new BlockList();
for (const [net, prefix] of [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16],
  ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15], ["224.0.0.0", 4], ["240.0.0.0", 4],
] as const) NON_PUBLIC.addSubnet(net, prefix, "ipv4");
// NB: no ::ffff:0:0/96 rule — Node's BlockList would then match EVERY IPv4 address.
// IPv4-mapped IPv6 addresses are unwrapped and checked as IPv4 instead (see isNonPublic).
for (const [net, prefix] of [["::", 128], ["::1", 128], ["fc00::", 7], ["fe80::", 10], ["ff00::", 8]] as const) {
  NON_PUBLIC.addSubnet(net, prefix, "ipv6");
}

const defaultLookup: Lookup = (host) => dnsLookup(host, { all: true, verbatim: true });

/** https + default port + no credentials + no IP literal (host allow-list NOT applied). */
export function assertPublicHttpsUrl(raw: string): URL {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new Error("Invalid URL");
  }
  if (u.protocol !== "https:") throw new Error(`Only https is allowed (${u.protocol})`);
  if (u.username || u.password) throw new Error("Credentials in URL are not allowed");
  if (u.port !== "") throw new Error("Non-default ports are not allowed");
  if (isIP(u.hostname.replace(/^\[|\]$/g, "")) !== 0) throw new Error("IP literals are not allowed");
  return u;
}

export function assertAllowedUrl(raw: string, allowedHosts: readonly string[]): URL {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new Error(`Invalid URL`);
  }
  if (u.protocol !== "https:") throw new Error(`Only https is allowed (${u.protocol})`);
  if (u.username || u.password) throw new Error("Credentials in URL are not allowed");
  if (u.port !== "") throw new Error("Non-default ports are not allowed");
  if (isIP(u.hostname.replace(/^\[|\]$/g, "")) !== 0) throw new Error("IP literals are not allowed");
  const host = u.hostname.toLowerCase();
  if (!allowedHosts.map((h) => h.toLowerCase()).includes(host)) {
    throw new Error(`Host ${host} is not allowed`);
  }
  return u;
}

export function isNonPublic(address: string): boolean {
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(address);
  if (mapped) return NON_PUBLIC.check(mapped[1], "ipv4");
  const v = isIP(address);
  if (v === 0) return true; // unparseable: fail closed
  return NON_PUBLIC.check(address, v === 6 ? "ipv6" : "ipv4");
}

async function assertPublicResolution(host: string, lookup: Lookup): Promise<void> {
  const addrs = await lookup(host);
  if (addrs.length === 0) throw new Error(`Host ${host} did not resolve`);
  for (const { address } of addrs) {
    if (isNonPublic(address)) throw new Error(`Host ${host} resolves to a non-public address`);
  }
}

async function fetchFollowing(url: string, opts: FetchOpts): Promise<Response> {
  const doFetch = opts.fetchImpl ?? fetch;
  const lookup = opts.lookup ?? defaultLookup;
  let current = assertAllowedUrl(url, opts.allowedHosts);
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    await assertPublicResolution(current.hostname, lookup);
    const auth = opts.authHeaders && current.hostname.toLowerCase() === opts.authHeaders.host.toLowerCase() ? opts.authHeaders.headers : {};
    const res = await doFetch(current.toString(), {
      redirect: "manual",
      headers: { "User-Agent": "Dataspace-PatchGate", ...auth },
      signal: AbortSignal.timeout(opts.timeoutMs),
    });
    if (res.status >= 300 && res.status < 400) {
      await res.body?.cancel().catch(() => undefined);
      const loc = res.headers.get("location");
      if (!loc) throw new Error("Redirect without location");
      const next = new URL(loc, current).toString();
      current = opts.redirects === "public" ? assertPublicHttpsUrl(next) : assertAllowedUrl(next, opts.allowedHosts);
      continue;
    }
    if (!res.ok) {
      await res.body?.cancel().catch(() => undefined);
      throw new Error(`HTTP ${res.status} from ${current.hostname}`);
    }
    return res;
  }
  throw new Error("Too many redirects");
}

export async function safeFetchText(url: string, opts: FetchOpts): Promise<string> {
  const res = await fetchFollowing(url, opts);
  const max = opts.maxTextBytes ?? DEFAULT_MAX_TEXT_BYTES;
  if (Number(res.headers.get("content-length") ?? "0") > max) {
    await res.body?.cancel().catch(() => undefined);
    throw new Error("Response too large");
  }
  if (!res.body) return "";
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > max) {
      await reader.cancel();
      throw new Error("Response too large");
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString("utf8");
}

export async function safeFetchJson(url: string, opts: FetchOpts): Promise<unknown> {
  return JSON.parse(await safeFetchText(url, opts)) as unknown;
}

export interface DownloadResult {
  sha256: string;
  size: number;
}

export async function safeDownload(
  url: string,
  destPath: string,
  opts: FetchOpts & { maxBytes: number },
): Promise<DownloadResult> {
  const res = await fetchFollowing(url, opts);
  const declared = Number(res.headers.get("content-length") ?? "0");
  if (declared > opts.maxBytes) {
    await res.body?.cancel().catch(() => undefined);
    throw new Error("Download exceeds size limit");
  }
  if (!res.body) throw new Error("Empty response body");

  const hash = createHash("sha256");
  const out = createWriteStream(destPath, { flags: "wx", mode: 0o600 });
  let size = 0;
  try {
    const reader = res.body.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > opts.maxBytes) {
        await reader.cancel();
        throw new Error("Download exceeds size limit");
      }
      hash.update(value);
      if (!out.write(value)) await new Promise<void>((r) => out.once("drain", () => r()));
    }
    await new Promise<void>((resolve, reject) => out.end((err?: Error | null) => (err ? reject(err) : resolve())));
    return { sha256: hash.digest("hex"), size };
  } catch (err: unknown) {
    // The stream opens the file asynchronously: wait until it is closed, otherwise an early failure could
    // delete "nothing" and the late open would leave a partial file behind (and block a retry: flags "wx").
    out.destroy();
    if (!out.closed) await new Promise<void>((r) => out.once("close", () => r()));
    await rm(destPath, { force: true });
    throw err;
  }
}
