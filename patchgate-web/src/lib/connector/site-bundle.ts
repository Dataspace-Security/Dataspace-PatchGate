import "server-only";
import { readFile, realpath, stat } from "node:fs/promises";
import { resolve, sep } from "node:path";
import { env } from "@/lib/env";

/**
 * Site bundles for the one-line web install (installers/site/web-install.md). Layout of the read-only volume:
 *
 *   <PATCHGATE_SITE_BUNDLE_DIR>/<version>/SHA256SUMS            outer checksums (build-site-bundle.sh)
 *   <PATCHGATE_SITE_BUNDLE_DIR>/<version>/SHA256SUMS.sig        optional detached Ed25519 signature
 *   <PATCHGATE_SITE_BUNDLE_DIR>/<version>/patchgate-site-<v>.tar.gz, …-online.tar.gz, install-site.sh
 *   <PATCHGATE_SITE_BUNDLE_DIR>/LATEST                          "latest" pointer (unless PATCHGATE_SITE_BUNDLE_LATEST)
 *
 * Only names listed in that version's SHA256SUMS are servable (strict allow-list, no path segments), and every
 * path is resolved with realpath containment, so neither "..", absolute names nor symlinks can leave the directory.
 */

export const BUNDLE_VERSION_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$/;
export const BUNDLE_FILE_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
export const SUMS_FILE = "SHA256SUMS";
export const SIG_FILE = "SHA256SUMS.sig";
export const SITE_SCRIPT = "install-site.sh";
export const URL_PLACEHOLDER = "__PATCHGATE_URL__";
export const KEY_PLACEHOLDER = "__PATCHGATE_BUNDLE_KEY__";
export const BUNDLE_KEY_RE = /^ed25519:[A-Za-z0-9+/]{43}=$/;
const MAX_SUMS_BYTES = 64 * 1024;
const MAX_SCRIPT_BYTES = 2 * 1024 * 1024;

export class BundleError extends Error {
  constructor(
    readonly status: 404 | 416,
    message: string,
  ) {
    super(message);
  }
}

export const NOT_CONFIGURED = "site bundles not configured";

export interface BundleConfig {
  dir: string;
  latest: string | null;
  /** Bundle-signing public key ("ed25519:<base64>") from server config — never from the bundle volume. */
  pubkey: string | null;
}

export function bundleConfig(
  e: { PATCHGATE_SITE_BUNDLE_DIR?: string; PATCHGATE_SITE_BUNDLE_LATEST?: string; PATCHGATE_SITE_BUNDLE_PUBKEY?: string } = env(),
): BundleConfig | null {
  if (!e.PATCHGATE_SITE_BUNDLE_DIR) return null;
  const pubkey = e.PATCHGATE_SITE_BUNDLE_PUBKEY && BUNDLE_KEY_RE.test(e.PATCHGATE_SITE_BUNDLE_PUBKEY) ? e.PATCHGATE_SITE_BUNDLE_PUBKEY : null;
  return { dir: resolve(e.PATCHGATE_SITE_BUNDLE_DIR), latest: e.PATCHGATE_SITE_BUNDLE_LATEST ?? null, pubkey };
}

function requireConfig(cfg: BundleConfig | null): BundleConfig {
  if (!cfg) throw new BundleError(404, NOT_CONFIGURED);
  return cfg;
}

/** Absolute, symlink-resolved path of `name` inside `base` (both already validated as single segments). */
async function contained(base: string, name: string): Promise<string> {
  const abs = resolve(base, name);
  if (!abs.startsWith(base + sep)) throw new BundleError(404, "not found");
  try {
    const [realBase, realAbs] = await Promise.all([realpath(base), realpath(abs)]);
    if (!realAbs.startsWith(realBase + sep)) throw new BundleError(404, "not found");
    return realAbs;
  } catch (err: unknown) {
    if (err instanceof BundleError) throw err;
    throw new BundleError(404, "not found");
  }
}

/** The concrete version for "latest" (env pointer, else <dir>/LATEST), or null when none is set. */
export async function latestVersion(cfg: BundleConfig): Promise<string | null> {
  if (cfg.latest) return cfg.latest;
  try {
    const first = (await readFile(resolve(cfg.dir, "LATEST"), "utf8")).split(/\r?\n/, 1)[0]?.trim() ?? "";
    return BUNDLE_VERSION_RE.test(first) ? first : null;
  } catch {
    return null;
  }
}

export interface ResolvedBundle {
  version: string;
  /** realpath of <dir>/<version> */
  path: string;
}

/** "latest" or a concrete version → its directory. Unknown / malformed → 404. */
export async function resolveBundle(cfgIn: BundleConfig | null, requested: string): Promise<ResolvedBundle> {
  const cfg = requireConfig(cfgIn);
  const version = requested === "latest" ? await latestVersion(cfg) : requested;
  if (!version || !BUNDLE_VERSION_RE.test(version)) throw new BundleError(404, "unknown bundle version");
  const path = await contained(cfg.dir, version);
  const s = await stat(path).catch(() => null);
  if (!s?.isDirectory()) throw new BundleError(404, "unknown bundle version");
  return { version, path };
}

/** Pure: `sha256sum` output (text or binary mode) → file name → sha256. Malformed lines and unsafe names are ignored. */
export function parseSha256Sums(text: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const line of text.split(/\r?\n/)) {
    const m = /^([a-fA-F0-9]{64}) [ *](.+)$/.exec(line.trim());
    if (!m) continue;
    const name = m[2].trim();
    if (BUNDLE_FILE_RE.test(name) && name !== SUMS_FILE && name !== SIG_FILE) out.set(name, m[1].toLowerCase());
  }
  return out;
}

export interface BundleFile {
  path: string;
  size: number;
  name: string;
}

async function fileIn(bundle: ResolvedBundle, name: string, maxBytes?: number): Promise<BundleFile> {
  if (!BUNDLE_FILE_RE.test(name)) throw new BundleError(404, "not found");
  const path = await contained(bundle.path, name);
  const s = await stat(path).catch(() => null);
  if (!s?.isFile() || (maxBytes !== undefined && s.size > maxBytes)) throw new BundleError(404, "not found");
  return { path, size: s.size, name };
}

export async function readSums(bundle: ResolvedBundle): Promise<{ text: string; files: Map<string, string> }> {
  const f = await fileIn(bundle, SUMS_FILE, MAX_SUMS_BYTES);
  const text = await readFile(f.path, "utf8");
  return { text, files: parseSha256Sums(text) };
}

/** The detached signature, or 404 when the bundle is unsigned. */
export async function signatureFile(bundle: ResolvedBundle): Promise<BundleFile> {
  return fileIn(bundle, SIG_FILE, 4096);
}

/** A file listed in the bundle's SHA256SUMS (strict allow-list); anything else → 404. */
export async function listedFile(bundle: ResolvedBundle, name: string): Promise<BundleFile & { sha256: string }> {
  const { files } = await readSums(bundle);
  const sha256 = files.get(name);
  if (!sha256) throw new BundleError(404, "not found");
  return { ...(await fileIn(bundle, name)), sha256 };
}

/**
 * GET /install/site.sh: the latest bundle's install-site.sh with the PatchGate URL and the bundle-signing key
 * baked in (the key comes from server config, so the script refuses a bundle the volume was tampered with).
 */
export async function siteScript(cfg: BundleConfig | null, serverUrl: string): Promise<{ version: string; body: string }> {
  const bundle = await resolveBundle(cfg, "latest");
  const f = await fileIn(bundle, SITE_SCRIPT, MAX_SCRIPT_BYTES);
  const origin = new URL(serverUrl).origin;
  const body = (await readFile(f.path, "utf8")).split(URL_PLACEHOLDER).join(origin);
  return { version: bundle.version, body: cfg?.pubkey ? body.split(KEY_PLACEHOLDER).join(cfg.pubkey) : body };
}

export type ByteRange = { start: number; end: number };

/**
 * Pure: a single `bytes=` range against `size` (RFC 9110). null = no/ignored Range (serve 200: absent,
 * other unit, multi-range or malformed); "unsatisfiable" = 416.
 */
export function parseRange(header: string | null, size: number): ByteRange | "unsatisfiable" | null {
  if (!header) return null;
  const m = /^bytes=(\d*)-(\d*)$/.exec(header.trim());
  if (!m || (m[1] === "" && m[2] === "")) return null;
  if (m[1] === "") {
    const suffix = Number(m[2]);
    if (suffix === 0) return "unsatisfiable";
    return size === 0 ? "unsatisfiable" : { start: Math.max(0, size - suffix), end: size - 1 };
  }
  const start = Number(m[1]);
  if (m[2] !== "" && Number(m[2]) < start) return null; // syntactically invalid (last < first): ignore Range
  if (start >= size) return "unsatisfiable";
  const end = m[2] === "" ? size - 1 : Math.min(Number(m[2]), size - 1);
  return { start, end };
}

export function contentTypeOf(name: string): string {
  if (name.endsWith(".tar.gz") || name.endsWith(".tgz")) return "application/gzip";
  if (name.endsWith(".sh")) return "text/x-shellscript; charset=utf-8";
  return "application/octet-stream";
}
