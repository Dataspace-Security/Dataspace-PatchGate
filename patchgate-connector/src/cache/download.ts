import { createHash, randomUUID } from "node:crypto";
import { createWriteStream } from "node:fs";
import { mkdir, open, readdir, rm, statfs } from "node:fs/promises";
import { dirname, join } from "node:path";
import { Transform, type TransformCallback } from "node:stream";
import { pipeline } from "node:stream/promises";
import { PatchGateError, type PatchGateClient } from "../pg-client.ts";
import { AbortedError } from "../util/backoff.ts";
import type { JobPackage } from "../protocol.ts";
import { headerValue } from "../util/http.ts";
import { renameRetry, rmRetry } from "../util/fsx.ts";
import type { Logger } from "../util/log.ts";
import type { TokenBucket } from "../util/token-bucket.ts";
import { JobError, permanent, transient, toJobError } from "../jobs/errors.ts";
import type { CacheIndex } from "./cache-index.ts";
import { cacheAbsPath, isSafeRepoPath } from "./paths.ts";

/**
 * CACHE_PACKAGE: stream GET /packages/{sha256} into a private temp file (size cap, SHA-256 while
 * streaming), verify, then atomically move to <cacheDir>/<repoPath> and record it in the index.
 */

export interface CacheDownloaderDeps {
  pg: PatchGateClient;
  index: CacheIndex;
  root: string;
  maxPackageBytes: number;
  minFreeBytes: number;
  /** cache.maxCacheBytes: total size cap of the cache (null = only the free-space floor applies). */
  maxCacheBytes?: number | null;
  /** Free bytes on the cache volume (default: statfs of root; tests inject). */
  freeBytes?: () => Promise<number | null>;
  /** Optional bandwidth cap for the download from PatchGate. */
  bucket?: TokenBucket;
  log: Logger;
}

export interface CacheResult {
  sha256: string;
  size: number;
  cachedPath: string;
}

class Meter extends Transform {
  readonly hash = createHash("sha256");
  bytes = 0;
  constructor(
    private readonly limit: number,
    private readonly bucket?: TokenBucket,
  ) {
    super();
  }
  override _transform(chunk: Buffer, _enc: BufferEncoding, cb: TransformCallback): void {
    this.bytes += chunk.length;
    if (this.bytes > this.limit) {
      cb(permanent(`package is larger than its declared size (${this.limit} bytes)`));
      return;
    }
    this.hash.update(chunk);
    if (!this.bucket) {
      cb(null, chunk);
      return;
    }
    this.bucket.take(chunk.length).then(() => cb(null, chunk), (err: unknown) => cb(err as Error));
  }
}

/** Free bytes available to this process on the volume holding `dir` (null if unknown). */
export async function volumeFreeBytes(dir: string): Promise<number | null> {
  try {
    const fs = await statfs(dir);
    return Number(fs.bavail) * Number(fs.bsize);
  } catch {
    return null;
  }
}

export class CacheDownloader {
  private readonly inflight = new Map<string, Promise<CacheResult>>();

  constructor(private readonly deps: CacheDownloaderDeps) {}

  private freeBytes(): Promise<number | null> {
    return this.deps.freeBytes ? this.deps.freeBytes() : volumeFreeBytes(this.deps.root);
  }

  /** Delete partial downloads left in <root>/.tmp by a crash. Call at startup, before any download. */
  async sweepTmp(): Promise<number> {
    const tmpDir = join(this.deps.root, ".tmp");
    let names: string[];
    try {
      names = await readdir(tmpDir);
    } catch {
      return 0;
    }
    for (const n of names) await rmRetry(join(tmpDir, n));
    if (names.length) this.deps.log.info("stale partial downloads removed", { count: names.length });
    return names.length;
  }

  /**
   * Make room for `needBytes` (LRU eviction of unpinned, unused packages). Also called periodically
   * with needBytes 0 to keep the cache under its cap.
   */
  async makeRoom(needBytes: number): Promise<{ removed: number; stillOver: boolean }> {
    const { index, log } = this.deps;
    const r = await index.evict({
      now: Date.now(),
      maxBytes: this.deps.maxCacheBytes ?? null,
      needBytes,
      freeBytes: () => this.freeBytes(),
      minFreeBytes: this.deps.minFreeBytes,
    });
    for (const e of r.removed) log.info("package evicted from cache (LRU; no unexpired job refers to it)", { repoPath: e.repoPath, size: e.size });
    return { removed: r.removed.length, stillOver: r.stillOver };
  }

  /** Concurrent jobs for the same path share one download. */
  cache(pkg: JobPackage, signal?: AbortSignal): Promise<CacheResult> {
    const running = this.inflight.get(pkg.repoPath);
    if (running) return running;
    const p = this.doCache(pkg, signal).finally(() => this.inflight.delete(pkg.repoPath));
    this.inflight.set(pkg.repoPath, p);
    return p;
  }

  private async doCache(pkg: JobPackage, signal?: AbortSignal): Promise<CacheResult> {
    const { index, root, log } = this.deps;
    if (!isSafeRepoPath(pkg.repoPath)) throw permanent("unsafe repoPath");
    if (pkg.size > this.deps.maxPackageBytes) throw permanent(`package exceeds cache.maxPackageBytes (${pkg.size} bytes)`);

    const existing = index.get(pkg.repoPath);
    if (existing) {
      if (existing.sha256 !== pkg.sha256) throw permanent("repoPath is already cached with a different SHA-256");
      if (await index.verify(pkg.repoPath)) return { sha256: existing.sha256, size: existing.size, cachedPath: existing.repoPath };
      log.warn("cached file failed re-verification; downloading again", { repoPath: pkg.repoPath });
      await index.remove(pkg.repoPath);
    }

    await mkdir(root, { recursive: true });
    await this.makeRoom(pkg.size);
    const free = await this.freeBytes();
    if (free !== null && free - pkg.size < this.deps.minFreeBytes) {
      log.error("cache disk below its free-space floor; CACHE_PACKAGE refused", { freeBytes: free, size: pkg.size, minFreeBytes: this.deps.minFreeBytes });
      throw permanent(
        `cache disk below its floor: ${free} bytes free, package needs ${pkg.size}, cache.minFreeBytes is ${this.deps.minFreeBytes}; every remaining package is still referenced by an unexpired job or being downloaded - free disk space or raise the volume size`,
      );
    }
    const max = this.deps.maxCacheBytes ?? null;
    if (max !== null && index.stats().bytes + pkg.size > max) {
      log.error("cache full (cache.maxCacheBytes); CACHE_PACKAGE refused", { bytes: index.stats().bytes, size: pkg.size, maxCacheBytes: max });
      throw permanent(`cache full: ${index.stats().bytes} bytes cached + ${pkg.size} > cache.maxCacheBytes ${max}; every remaining package is still referenced by an unexpired job`);
    }

    const tmpDir = join(root, ".tmp");
    await mkdir(tmpDir, { recursive: true, mode: 0o700 });
    const tmp = join(tmpDir, randomUUID());
    try {
      const { res, abort } = await this.deps.pg.downloadPackage(pkg.sha256, signal);
      const declared = Number(headerValue(res.headers, "content-length") ?? "NaN");
      if (Number.isFinite(declared) && declared !== pkg.size) {
        abort(new Error("size mismatch"));
        throw permanent(`server sent ${declared} bytes, job declares ${pkg.size}`);
      }
      const meter = new Meter(pkg.size, this.deps.bucket);
      await pipeline(res, meter, createWriteStream(tmp, { flags: "wx", mode: 0o644 }), { signal });
      if (meter.bytes !== pkg.size) throw transient(`download truncated (${meter.bytes}/${pkg.size} bytes)`);
      const sha = meter.hash.digest("hex");
      if (sha !== pkg.sha256) throw permanent("SHA-256 mismatch: downloaded bytes do not match the signed job");

      const fh = await open(tmp, "r+"); // r+: Windows refuses fsync on read-only handles
      try {
        await fh.sync();
      } finally {
        await fh.close();
      }
      const dest = cacheAbsPath(root, pkg.repoPath);
      await mkdir(dirname(dest), { recursive: true });
      await renameRetry(tmp, dest);
      await index.put({
        repoPath: pkg.repoPath,
        sha256: pkg.sha256,
        size: pkg.size,
        kind: pkg.kind,
        wingetId: pkg.wingetId,
        version: pkg.version,
        cachedAt: new Date().toISOString(),
      });
      log.info("package cached", { repoPath: pkg.repoPath, sha256: pkg.sha256, size: pkg.size });
      return { sha256: pkg.sha256, size: pkg.size, cachedPath: pkg.repoPath };
    } catch (err) {
      await rmRetry(tmp).catch(() => rm(tmp, { force: true }).catch(() => undefined));
      if (err instanceof JobError) throw err;
      if (err instanceof PatchGateError || err instanceof AbortedError) throw toJobError(err);
      // stream / socket failures mid-download are transient
      throw transient(`package download failed: ${err instanceof Error ? err.message : "unknown error"}`);
    }
  }
}
