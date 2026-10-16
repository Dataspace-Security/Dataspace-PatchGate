import { realpath } from "node:fs/promises";
import { resolve, sep } from "node:path";

/**
 * Path safety for the package cache (adapted from patchgate-web/src/lib/fetch/repo.ts).
 * A cache path is a repo-relative path from a signed job, e.g. "pkgs/7zip/24.08/7z2408-x64.msi".
 */

// Alphanumeric first and last char: blocks ".", "..", dot-dirs (.tmp) and Windows trailing-dot
// aliases ("foo." == "foo"); only the protocol's character set in between.
const SEGMENT = /^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9_-])?$/;
export const SERVED_ROOTS = ["pkgs", "tactical", "winupdate"] as const;
const MAX_SEGMENTS = 8;
const MAX_LEN = 256;

export function isSafeRepoPath(rel: string): boolean {
  if (typeof rel !== "string" || rel.length === 0 || rel.length > MAX_LEN) return false;
  const segs = rel.split("/");
  if (segs.length < 2 || segs.length > MAX_SEGMENTS) return false;
  if (!segs.every((s) => SEGMENT.test(s))) return false;
  return (SERVED_ROOTS as readonly string[]).includes(segs[0] ?? "");
}

export function assertRepoPath(rel: string): string {
  if (!isSafeRepoPath(rel)) throw new Error("invalid cache path");
  return rel;
}

/** Absolute path inside root; throws if resolution escapes the root. */
export function cacheAbsPath(root: string, rel: string): string {
  const base = resolve(root);
  const abs = resolve(base, assertRepoPath(rel));
  if (!abs.startsWith(base + sep)) throw new Error("path escapes cache root");
  return abs;
}

/** Resolve symlinks and confirm the real file is still inside the cache root. */
export async function realCacheFile(root: string, rel: string): Promise<string> {
  const abs = cacheAbsPath(root, rel);
  const [realRoot, realFile] = await Promise.all([realpath(resolve(root)), realpath(abs)]);
  if (!realFile.startsWith(realRoot + sep)) throw new Error("path escapes cache root");
  return realFile;
}
