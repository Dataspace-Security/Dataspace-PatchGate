import { mkdir, realpath, rename, rm } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { dirname, resolve, sep } from "node:path";

/**
 * Internal package repository on disk (served read-only at /repo to offline consumers).
 * Files land in .tmp first and are only moved into the served tree after verification.
 */

// Alphanumeric first and last char: blocks ".", "..", dot-dirs (.tmp/.pending) and Windows
// trailing-dot aliases ("foo." == "foo").
const SEGMENT = /^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9_-])?$/;
// Only these top-level trees are ever served. Staging (.tmp) and unapproved mirrors (.pending)
// live beside them and can't be reached — not even via 8.3 short names like PENDIN~1.
export const SERVED_ROOTS = ["pkgs", "tactical", "winupdate"] as const;

export function assertRepoRelPath(rel: string): string {
  const segs = rel.split("/");
  if (segs.length < 2 || segs.length > 8 || !segs.every((s) => SEGMENT.test(s))) {
    throw new Error("Invalid repo path");
  }
  if (!(SERVED_ROOTS as readonly string[]).includes(segs[0])) throw new Error("Invalid repo path");
  return rel;
}

/** Absolute path inside root; throws if resolution escapes the root. */
export function repoAbsPath(root: string, rel: string): string {
  const base = resolve(root);
  const abs = resolve(base, assertRepoRelPath(rel));
  if (!abs.startsWith(base + sep)) throw new Error("Path escapes repository root");
  return abs;
}

/** Resolve symlinks and confirm the real file is still inside the repository root. */
export async function realRepoFile(root: string, rel: string): Promise<string> {
  const abs = repoAbsPath(root, rel);
  const [realRoot, realFile] = await Promise.all([realpath(resolve(root)), realpath(abs)]);
  if (!realFile.startsWith(realRoot + sep)) throw new Error("Path escapes repository root");
  return realFile;
}

const PENDING_DIR = ".pending"; // not servable: repo paths must start with an alphanumeric

/** Where a downloaded-but-unapproved file waits (outside the served tree) for an admin decision. */
export function pendingAbs(root: string, rel: string): string {
  const base = resolve(root, PENDING_DIR);
  const abs = resolve(base, assertRepoRelPath(rel));
  if (!abs.startsWith(base + sep)) throw new Error("Path escapes pending dir");
  return abs;
}

export async function newTempFile(root: string): Promise<string> {
  const dir = resolve(root, ".tmp");
  await mkdir(dir, { recursive: true, mode: 0o700 });
  return resolve(dir, randomUUID());
}

/** Atomically move a verified temp file into the served tree. */
export async function publishFile(root: string, tempPath: string, rel: string): Promise<void> {
  const dest = repoAbsPath(root, rel);
  await mkdir(dirname(dest), { recursive: true });
  await rename(tempPath, dest);
}

export async function discardTemp(tempPath: string): Promise<void> {
  await rm(tempPath, { force: true });
}
