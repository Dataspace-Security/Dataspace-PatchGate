import { lookup as dnsLookup } from "node:dns/promises";
import { assertAllowedUrl, isNonPublic } from "@/lib/fetch/http";

/**
 * HEAD request with the same guards as safeFetch (https, exact host allow-list, public DNS only) and NO
 * redirects: lets the monthly scan-catalog check compare validators without pulling ~700 MB.
 */

export interface RemoteValidators {
  etag: string | null;
  lastModified: string | null;
  size: number | null;
}

type Lookup = (host: string) => Promise<{ address: string }[]>;

export async function probeHead(
  url: string,
  opts: { allowedHosts: readonly string[]; timeoutMs: number; fetchImpl?: typeof fetch; lookup?: Lookup },
): Promise<RemoteValidators> {
  const u = assertAllowedUrl(url, opts.allowedHosts);
  const addrs = await (opts.lookup ?? ((h: string) => dnsLookup(h, { all: true, verbatim: true })))(u.hostname);
  if (addrs.length === 0 || addrs.some((a) => isNonPublic(a.address))) throw new Error(`Host ${u.hostname} does not resolve to public addresses`);
  const res = await (opts.fetchImpl ?? fetch)(u.toString(), {
    method: "HEAD",
    redirect: "manual",
    headers: { "User-Agent": "Dataspace-PatchGate" },
    signal: AbortSignal.timeout(opts.timeoutMs),
  });
  await res.body?.cancel().catch(() => undefined);
  if (res.status !== 200) throw new Error(`HTTP ${res.status} from ${u.hostname}`);
  const len = Number(res.headers.get("content-length") ?? "NaN");
  const clip = (v: string | null) => (v ? v.slice(0, 200) : null);
  return { etag: clip(res.headers.get("etag")), lastModified: clip(res.headers.get("last-modified")), size: Number.isFinite(len) && len > 0 ? len : null };
}
