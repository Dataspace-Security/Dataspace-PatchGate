/**
 * Pure rules for Microsoft update content (no I/O): which URLs PatchGate may fetch, how a scan-reported
 * URL is normalised, what the expected digest is, and how files are named in the repository.
 *
 * Trust model: a WU_SCAN result comes from a bank PC and is UNTRUSTED; it only says which update GUIDs apply.
 * The update -> file binding comes from the Microsoft Update Catalog (catalog.ts). A file becomes installable
 * only if (1) the catalog lists it for that update, (2) its URL is on the exact Microsoft host allow-list,
 * (3) the bytes match the catalog SHA-1 (also embedded in the name) and SHA-256, (4) it carries a valid
 * Authenticode signature whose organisation is exactly "Microsoft Corporation", and (5) the quarantine soak
 * has passed.
 */

/** Microsoft's offline scan catalog. download.windowsupdate.com (the fwlink target) has no TLS. */
export const WSUSSCN2_URL = "https://catalog.s.download.windowsupdate.com/microsoftupdate/v6/wsusscan/wsusscn2.cab";

/** Pin for every Microsoft file (cab, msu): exact organisation match on the signer certificate. */
export const MICROSOFT_PUBLISHER = "O=Microsoft Corporation";

const WU_TLS_HOST = "catalog.s.download.windowsupdate.com";
const DELIVERY_TLS_HOST = "catalog.sf.dl.delivery.mp.microsoft.com";

/** Hosts PatchGate itself connects to (TLS). Exact names, never suffixes. */
export const FETCH_HOSTS = [WU_TLS_HOST, DELIVERY_TLS_HOST] as const;

/** Windows Update CDN paths ("/c/msdownload/update/software/secu/2025/04/<name>"). */
const WU_PATH_RE = /^\/(?:[a-z]\/)?msdownload\/update\/(?:software|driver|v3-19990518)\/[A-Za-z0-9._/-]{1,400}$/;
/** Delivery-optimisation CDN paths ("/filestreamingservice/files/<guid>/public/<name>"). */
const DELIVERY_PATH_RE = /^\/filestreamingservice\/files\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/public\/[A-Za-z0-9._-]{1,255}$/i;

/**
 * Hosts the offline scan catalog references (observed in wsusscn2.cab package.xml, 2026-10: http only).
 * Each maps to the Microsoft TLS name that serves the SAME path; anything else is rejected.
 */
const HOST_RULES: Readonly<Record<string, { tls: string; path: RegExp }>> = {
  "download.windowsupdate.com": { tls: WU_TLS_HOST, path: WU_PATH_RE },
  "www.download.windowsupdate.com": { tls: WU_TLS_HOST, path: WU_PATH_RE },
  [WU_TLS_HOST]: { tls: WU_TLS_HOST, path: WU_PATH_RE },
  "dl.delivery.mp.microsoft.com": { tls: DELIVERY_TLS_HOST, path: DELIVERY_PATH_RE },
  [DELIVERY_TLS_HOST]: { tls: DELIVERY_TLS_HOST, path: DELIVERY_PATH_RE },
};

export const WINUPDATE_KINDS = ["msu", "cab"] as const;
export type WinUpdateKind = (typeof WINUPDATE_KINDS)[number];

const GUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SEGMENT_RE = /^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9_-])?$/;

export type UrlCheck = { ok: true; url: string; name: string; kind: WinUpdateKind } | { ok: false; reason: string };

/**
 * Validate + normalise a scan-reported download URL to the https URL PatchGate fetches.
 * Rejects: non-http(s), credentials, ports, query/fragment, unknown hosts, unexpected paths,
 * file types other than .msu/.cab (express/delta .psf, .exe, .esd are not installed this way).
 */
export function normalizeUpdateUrl(raw: string): UrlCheck {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return { ok: false, reason: "invalid URL" };
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") return { ok: false, reason: "scheme not allowed" };
  if (u.username || u.password) return { ok: false, reason: "credentials in URL" };
  if (u.port !== "") return { ok: false, reason: "non-default port" };
  if (u.search !== "" || u.hash !== "") return { ok: false, reason: "query or fragment not allowed" };
  const host = u.hostname.toLowerCase();
  const rule = Object.hasOwn(HOST_RULES, host) ? HOST_RULES[host] : undefined;
  if (!rule) return { ok: false, reason: `host ${host.slice(0, 100)} is not an allow-listed Microsoft host` };
  if (!rule.path.test(u.pathname) || u.pathname.includes("..") || u.pathname.includes("//")) return { ok: false, reason: "unexpected download path" };
  const name = u.pathname.slice(u.pathname.lastIndexOf("/") + 1).toLowerCase();
  const kind = fileKind(name);
  if (!kind) return { ok: false, reason: `unsupported file type (${name.slice(name.lastIndexOf(".") + 1).slice(0, 10)})` };
  if (!SEGMENT_RE.test(name)) return { ok: false, reason: "unsafe file name" };
  return { ok: true, url: `https://${rule.tls}${u.pathname}`, name, kind };
}

export function fileKind(name: string): WinUpdateKind | null {
  const m = /\.([a-z0-9]{1,8})$/i.exec(name);
  const ext = m?.[1]?.toLowerCase();
  return ext === "msu" || ext === "cab" ? ext : null;
}

/** Microsoft names CDN files "<name>_<sha1 hex>.<ext>": the SHA-1 of the bytes. */
export function sha1FromName(name: string): string | null {
  const m = /_([0-9a-f]{40})\.[a-z0-9]{1,8}$/i.exec(name);
  return m ? m[1].toLowerCase() : null;
}

/** Digest strings from WUA may be hex or base64; return lower-case hex of the expected length, or null. */
export function normalizeDigest(value: string | null | undefined, bytes: 20 | 32): string | null {
  if (!value) return null;
  const v = value.trim();
  if (new RegExp(`^[0-9a-fA-F]{${bytes * 2}}$`).test(v)) return v.toLowerCase();
  if (/^[A-Za-z0-9+/]+={0,2}$/.test(v)) {
    const buf = Buffer.from(v, "base64");
    if (buf.length === bytes) return buf.toString("hex");
  }
  return null;
}

/** KB number in a Microsoft file name ("windows10.0-kb5034441-x64_...") — must agree with the update's KB. */
export function kbFromName(name: string): string | null {
  const m = /(?:^|[-_.])kb(\d{4,8})(?=[-_.]|$)/i.exec(name);
  return m ? `KB${m[1]}` : null;
}

/** Normalise WUA's KB article id ("5034441", "KB5034441") to "KB5034441" or null. */
export function normalizeKb(kb: string | null | undefined): string | null {
  const m = /^(?:KB)?(\d{4,8})$/i.exec((kb ?? "").trim());
  return m ? `KB${m[1]}` : null;
}

export function normalizeGuid(id: string): string | null {
  const g = id.trim().toLowerCase();
  return GUID_RE.test(g) ? g : null;
}

/** Placeholder title for an update nobody has looked up yet (no PC-supplied text is ever shown). */
export function pendingTitle(updateId: string): string {
  return `Windows update ${updateId} (pending Microsoft Update Catalog lookup)`;
}

/** Repository path of a verified update file: winupdate/<updateId>/<file name>. */
export function updateFileRepoPath(updateId: string, name: string): string {
  const id = normalizeGuid(updateId);
  if (!id || !SEGMENT_RE.test(name)) throw new Error("invalid update file path");
  return `winupdate/${id}/${name}`;
}

/** Repository path of a verified scan catalog (content-addressed, so a new month never overwrites a cached one). */
export function scanCabRepoPath(sha256: string): string {
  if (!/^[a-f0-9]{64}$/.test(sha256)) throw new Error("invalid sha256");
  return `winupdate/wsusscan/${sha256.slice(0, 16)}/wsusscn2.cab`;
}

/** Job-package version for a scan catalog: UTC date of download + short hash, e.g. "20261014-1a2b3c4d". */
export function scanCabVersion(createdAt: Date, sha256: string): string {
  const d = createdAt.toISOString().slice(0, 10).replace(/-/g, "");
  return `${d}-${sha256.slice(0, 8)}`;
}
