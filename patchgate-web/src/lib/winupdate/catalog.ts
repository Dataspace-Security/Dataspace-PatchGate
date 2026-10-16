/**
 * AUTHORITATIVE source of what a Windows update IS and WHICH files it installs: the Microsoft Update
 * Catalog (https://www.catalog.update.microsoft.com, TLS, exact host allow-list). PC scan reports only tell
 * PatchGate which update GUIDs apply to a PC; title, KB, severity and the update → file binding (URL,
 * SHA-1, SHA-256) are looked up here, server-side, once per update.
 *
 *  - DownloadDialog.aspx?updateIDs=[…]  → official download URLs + SHA-1 ("digest") + SHA-256 per file
 *  - ScopedViewInline.aspx?updateid=…   → title, classification, MSRC severity, KB article
 *
 * Parsing is pure (unit-tested against captured responses); fetching goes through the safe fetcher.
 */
import { safeFetchText } from "@/lib/fetch/http";
import { fileKind, kbFromName, normalizeDigest, normalizeGuid, normalizeKb, normalizeUpdateUrl, sha1FromName, type WinUpdateKind } from "./microsoft";

export const CATALOG_HOST = "www.catalog.update.microsoft.com";
/** Hosts the catalog lookup may connect to (exact names; redirects must stay on them). */
export const CATALOG_HOSTS = [CATALOG_HOST] as const;
/** Per-update cap on bound files (a cumulative update with its checkpoint is 2; language packs are refused). */
export const WU_MAX_FILES_PER_UPDATE = 10;
const MAX_CATALOG_RESPONSE_BYTES = 2_000_000;
const CATALOG_TIMEOUT_MS = 30_000;

export interface CatalogFileInfo {
  url: string;
  fileName: string;
  digest: string | null; // base64 SHA-1
  sha256: string | null; // base64 SHA-256
  languages: string;
}

export interface CatalogDetails {
  title: string | null;
  kb: string | null;
  msrcSeverity: string | null;
  classification: string | null;
}

export type CatalogLookup =
  | { found: false }
  | { found: true; updateId: string; title: string; details: CatalogDetails; files: CatalogFileInfo[] };

export function downloadDialogUrl(updateId: string): string {
  const id = normalizeGuid(updateId);
  if (!id) throw new Error("invalid update id");
  const ids = JSON.stringify([{ size: 0, languages: "", uidInfo: id, updateID: id }]);
  return `https://${CATALOG_HOST}/DownloadDialog.aspx?updateIDs=${encodeURIComponent(ids)}`;
}

export function detailsUrl(updateId: string): string {
  const id = normalizeGuid(updateId);
  if (!id) throw new Error("invalid update id");
  return `https://${CATALOG_HOST}/ScopedViewInline.aspx?updateid=${id}`;
}

/** Undo the JS single-quoted string escaping used by DownloadDialog.aspx. */
function jsUnescape(s: string): string {
  return s.replace(/\\(u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|.)/g, (_m, e: string) => {
    if (e.length === 5 && e[0] === "u") return String.fromCharCode(parseInt(e.slice(1), 16));
    if (e.length === 3 && e[0] === "x") return String.fromCharCode(parseInt(e.slice(1), 16));
    return e === "n" ? "\n" : e === "t" ? "\t" : e;
  });
}

function htmlDecode(s: string): string {
  return s
    .replace(/&#(\d{1,6});/g, (_m, d: string) => String.fromCharCode(Number(d)))
    .replace(/&#x([0-9a-f]{1,6});/gi, (_m, h: string) => String.fromCharCode(parseInt(h, 16)))
    .replace(/&quot;/g, '"')
    .replace(/&#39;|&apos;/g, "'")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&");
}

const clean = (s: string, max: number) => htmlDecode(s).replace(/\s+/g, " ").trim().slice(0, max);

/** Parse DownloadDialog.aspx for ONE requested update (downloadInformation[0]). Unknown GUID → found:false. */
export function parseDownloadDialog(html: string, updateId: string): { found: false } | { found: true; title: string; files: CatalogFileInfo[] } {
  const id = normalizeGuid(updateId);
  const props = new Map<string, string>();
  const re = /downloadInformation\[0\]\.([A-Za-z0-9]+(?:\[\d{1,3}\]\.[A-Za-z0-9]+)?)\s*=\s*'((?:[^'\\\r\n]|\\.){0,4000})'\s*;/g;
  for (let m = re.exec(html); m; m = re.exec(html)) props.set(m[1], jsUnescape(m[2]));
  const reported = normalizeGuid(props.get("updateID") ?? "");
  if (!id || !reported || reported !== id) return { found: false };
  const files: CatalogFileInfo[] = [];
  for (let i = 0; props.has(`files[${i}].url`); i++) {
    const get = (k: string) => props.get(`files[${i}].${k}`) ?? "";
    files.push({ url: get("url"), fileName: get("fileName"), digest: get("digest") || null, sha256: get("sha256") || null, languages: get("languages").trim() });
  }
  return { found: true, title: clean(props.get("enTitle") ?? "", 1000), files };
}

function spanText(html: string, id: string): string | null {
  const m = new RegExp(`<span[^>]*id="${id}"[^>]*>([\\s\\S]{0,2000}?)</span>`).exec(html);
  const v = m ? clean(m[1].replace(/<[^>]*>/g, " "), 1000) : "";
  return v || null;
}

/** Text that follows a label span inside its <div> (classification, KB numbers). */
function labelledText(html: string, labelId: string): string | null {
  const m = new RegExp(`<span[^>]*id="${labelId}"[^>]*>[\\s\\S]{0,200}?</span>([\\s\\S]{0,2000}?)</div>`).exec(html);
  const v = m ? clean(m[1].replace(/<[^>]*>/g, " "), 1000) : "";
  return v || null;
}

/** Parse ScopedViewInline.aspx (details page). Returns null when it is not the page of this update. */
export function parseDetails(html: string, updateId: string): CatalogDetails | null {
  const id = normalizeGuid(updateId);
  const shown = normalizeGuid(spanText(html, "ScopedViewHandler_UpdateID") ?? "");
  if (!id || shown !== id) return null;
  const severity = spanText(html, "ScopedViewHandler_msrcSeverity");
  const kbText = labelledText(html, "ScopedViewHandler_labelKBArticle_Separator");
  const kb = kbText ? normalizeKb(kbText.split(/[\s,]+/)[0]) : null;
  const classification = labelledText(html, "ScopedViewHandler_labelClassification_Separator");
  return {
    title: spanText(html, "ScopedViewHandler_titleText"),
    kb,
    msrcSeverity: severity && severity.toLowerCase() !== "n/a" ? severity.slice(0, 32) : null,
    classification: classification && classification.toLowerCase() !== "n/a" ? classification.slice(0, 100) : null,
  };
}

/** "(KB5044284)" in a catalog title. */
export function kbFromTitle(title: string): string | null {
  const m = /\bKB(\d{4,8})\b/i.exec(title);
  return m ? `KB${m[1]}` : null;
}

export interface BoundFile {
  url: string;
  name: string;
  kind: WinUpdateKind;
  sha1: string;
  expectedSha256: string | null;
  ordinal: number;
}

export type CatalogBinding =
  | { ok: true; title: string; kb: string | null; msrcSeverity: string | null; classification: string | null; files: BoundFile[] }
  | { ok: false; reason: string; title: string | null; kb: string | null; msrcSeverity: string | null; classification: string | null };

/**
 * Pure: turn a catalog lookup into the update's file binding, or the reason it cannot be delivered.
 * Every file must be an allow-listed Microsoft .msu/.cab with a catalog SHA-1 (agreeing with the SHA-1 in its
 * name); at most WU_MAX_FILES_PER_UPDATE files; language-specific file sets are refused; when the update has a
 * KB and file names carry KBs, at least one file is the update's own KB. Other-KB files (checkpoint cumulative
 * updates) are prerequisites and ordered first.
 */
export function planCatalogBinding(lookup: Extract<CatalogLookup, { found: true }>): CatalogBinding {
  const d = lookup.details;
  const title = (d.title ?? lookup.title).slice(0, 1000) || lookup.updateId;
  const kb = d.kb ?? kbFromTitle(title);
  const meta = { title, kb, msrcSeverity: d.msrcSeverity, classification: d.classification };
  const fail = (reason: string): CatalogBinding => ({ ok: false, reason, ...meta });

  if (lookup.files.length === 0) return fail("Microsoft publishes no downloadable files for this update");
  if (lookup.files.length > WU_MAX_FILES_PER_UPDATE) return fail(`too many files (${lookup.files.length} > ${WU_MAX_FILES_PER_UPDATE})`);
  const langs = new Set(lookup.files.map((f) => f.languages.toLowerCase()));
  if (langs.size > 1) return fail("language-specific files are not supported");

  const seen = new Set<string>();
  const files: Omit<BoundFile, "ordinal">[] = [];
  for (const f of lookup.files) {
    const u = normalizeUpdateUrl(f.url);
    if (!u.ok) return fail(`catalog file rejected: ${u.reason}`);
    if (!fileKind(u.name)) return fail("unsupported file type");
    const sha1 = normalizeDigest(f.digest, 20);
    if (!sha1) return fail(`catalog file ${u.name} has no SHA-1`);
    const nameSha1 = sha1FromName(u.name);
    if (nameSha1 && nameSha1 !== sha1) return fail(`catalog SHA-1 of ${u.name} differs from its name`);
    const expectedSha256 = f.sha256 === null ? null : normalizeDigest(f.sha256, 32);
    if (f.sha256 !== null && expectedSha256 === null) return fail(`catalog SHA-256 of ${u.name} is malformed`);
    if (seen.has(u.url)) continue;
    seen.add(u.url);
    files.push({ url: u.url, name: u.name, kind: u.kind, sha1, expectedSha256 });
  }

  const fileKbs = files.map((f) => kbFromName(f.name));
  if (kb && fileKbs.some((k) => k !== null) && !fileKbs.includes(kb)) return fail(`no file of ${kb} in the catalog file set`);
  const prereq = (i: number) => (kb && fileKbs[i] && fileKbs[i] !== kb ? 0 : 1);
  const ordered = files.map((f, i) => ({ f, i })).sort((a, b) => prereq(a.i) - prereq(b.i) || a.i - b.i);
  return { ok: true, ...meta, files: ordered.map(({ f }, ordinal) => ({ ...f, ordinal })) };
}

export type CatalogFetcher = (url: string) => Promise<string>;

export function defaultCatalogFetcher(): CatalogFetcher {
  return (url) => safeFetchText(url, { allowedHosts: CATALOG_HOSTS, redirects: "allowlist", timeoutMs: CATALOG_TIMEOUT_MS, maxTextBytes: MAX_CATALOG_RESPONSE_BYTES });
}

/** Look one update up in the Microsoft Update Catalog (network; never call inside a DB transaction). */
export async function lookupCatalogUpdate(updateId: string, fetchText: CatalogFetcher = defaultCatalogFetcher()): Promise<CatalogLookup> {
  const id = normalizeGuid(updateId);
  if (!id) return { found: false };
  const dialog = parseDownloadDialog(await fetchText(downloadDialogUrl(id)), id);
  if (!dialog.found) return { found: false };
  const details = parseDetails(await fetchText(detailsUrl(id)), id) ?? { title: null, kb: null, msrcSeverity: null, classification: null };
  return { found: true, updateId: id, title: dialog.title, details, files: dialog.files };
}
