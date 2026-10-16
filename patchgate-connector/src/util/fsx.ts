import { randomUUID } from "node:crypto";
import { createReadStream } from "node:fs";
import { mkdir, open, readdir, rename, rm } from "node:fs/promises";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";

/**
 * Windows: anti-virus scanners, the search indexer and backup agents briefly open files without
 * FILE_SHARE_DELETE, so rename/unlink fail with EPERM/EBUSY/EACCES for a few hundred ms. Retry those
 * with backoff instead of failing a job (EBUSY is retried on every platform).
 */
export function isTransientFsError(err: unknown, platform: NodeJS.Platform = process.platform): boolean {
  const code = (err as NodeJS.ErrnoException | undefined)?.code;
  if (code === "EBUSY") return true;
  return platform === "win32" && (code === "EPERM" || code === "EACCES");
}

export interface FsRetryOptions {
  attempts?: number;
  baseMs?: number;
  platform?: NodeJS.Platform;
}

export async function withFsRetry<T>(fn: () => Promise<T>, o: FsRetryOptions = {}): Promise<T> {
  const attempts = o.attempts ?? 8;
  const base = o.baseMs ?? 25;
  for (let i = 0; ; i++) {
    try {
      return await fn();
    } catch (err) {
      if (i >= attempts - 1 || !isTransientFsError(err, o.platform)) throw err;
      await new Promise((r) => setTimeout(r, Math.min(2000, base * 2 ** i)));
    }
  }
}

export const renameRetry = (from: string, to: string, o?: FsRetryOptions): Promise<void> => withFsRetry(() => rename(from, to), o);
export const rmRetry = (path: string, o?: FsRetryOptions): Promise<void> => withFsRetry(() => rm(path, { force: true }), o);

/**
 * Write a file atomically: temp file in the same directory → fsync → rename.
 * Readers see either the old or the new content, never a partial file.
 */
export async function writeFileAtomic(path: string, data: string | Uint8Array, mode = 0o600): Promise<void> {
  const dir = dirname(path);
  await mkdir(dir, { recursive: true });
  const tmp = join(dir, `.${randomUUID()}.tmp`);
  const fh = await open(tmp, "wx", mode);
  try {
    await fh.writeFile(data);
    await fh.sync();
  } finally {
    await fh.close();
  }
  try {
    await renameRetry(tmp, path);
  } catch (err) {
    await rm(tmp, { force: true });
    throw err;
  }
}

const ATOMIC_TMP_RE = /^\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.tmp$/;

/** Remove temp files left behind by writeFileAtomic after a crash (call at startup only). */
export async function sweepAtomicTemps(dir: string): Promise<number> {
  let names: string[];
  try {
    names = await readdir(dir);
  } catch {
    return 0;
  }
  let n = 0;
  for (const name of names) {
    if (!ATOMIC_TMP_RE.test(name)) continue;
    await rmRetry(join(dir, name));
    n++;
  }
  return n;
}

/** Streaming SHA-256 of a file (lowercase hex) and its size. */
export async function hashFile(path: string): Promise<{ sha256: string; size: number }> {
  const hash = createHash("sha256");
  let size = 0;
  for await (const chunk of createReadStream(path, { highWaterMark: 1024 * 1024 })) {
    const buf = chunk as Buffer;
    size += buf.length;
    hash.update(buf);
  }
  return { sha256: hash.digest("hex"), size };
}
