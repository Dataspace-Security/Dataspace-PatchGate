import { readFile, stat } from "node:fs/promises";
import { z } from "zod";
import { hashFile, rmRetry, writeFileAtomic } from "../util/fsx.ts";
import type { Logger } from "../util/log.ts";
import { cacheAbsPath, isSafeRepoPath, realCacheFile } from "./paths.ts";

/**
 * The verified cache index: the ONLY list of files the cache server will serve and DEPLOY_PACKAGE
 * will use. An entry is added only after the file's SHA-256 and size matched the signed job.
 */

const entrySchema = z.object({
  repoPath: z.string().refine(isSafeRepoPath, "unsafe repo path"),
  sha256: z.string().regex(/^[a-f0-9]{64}$/),
  size: z.number().int().positive(),
  kind: z.enum(["msi", "exe", "agent", "msu", "cab", "wsusscan"]),
  wingetId: z.string().max(128),
  version: z.string().max(64),
  cachedAt: z.string(),
});
export type CacheEntry = z.infer<typeof entrySchema>;

/** pins: repoPath → epoch ms until which a not-yet-expired job refers to it (eviction-protected). */
const fileSchema = z.object({ v: z.literal(1), entries: z.array(entrySchema), pins: z.record(z.string(), z.number()).optional() });

/** A pin is only re-persisted when it moves by more than this (a wave of deploy jobs = one write). */
const PIN_PERSIST_SLACK_MS = 10 * 60_000;

export interface EvictOptions {
  now: number;
  /** cache.maxCacheBytes (null = no size cap). */
  maxBytes: number | null;
  /** Bytes about to be added (a download in progress). */
  needBytes: number;
  /** Free bytes on the cache volume (null = unknown). */
  freeBytes: () => Promise<number | null>;
  minFreeBytes: number;
}

export interface EvictResult {
  removed: CacheEntry[];
  /** Still over the size cap / under the free-space floor after evicting everything evictable. */
  stillOver: boolean;
}

const VERIFY_TTL_MS = 60_000;

interface VerifyMemo {
  size: number;
  mtimeMs: number;
  ino: number;
  at: number;
}

export class CacheIndex {
  private readonly entries = new Map<string, CacheEntry>();
  private chain: Promise<void> = Promise.resolve();
  private readonly inflight = new Map<string, Promise<boolean>>();
  private readonly memo = new Map<string, VerifyMemo>();
  /** Open readers per path (cache server downloads): such files are never deleted under them. */
  private readonly refs = new Map<string, number>();
  /** Removed from the index while still being served: deleted when the last reader finishes. */
  private readonly pendingDelete = new Set<string>();
  private readonly lastUsed = new Map<string, number>();
  private readonly pins = new Map<string, number>();

  private constructor(
    readonly indexFile: string,
    readonly root: string,
  ) {}

  /** Load the index; entries whose file vanished or changed size are dropped. */
  static async open(indexFile: string, root: string, log?: Logger): Promise<CacheIndex> {
    const idx = new CacheIndex(indexFile, root);
    let text: string | undefined;
    try {
      text = await readFile(indexFile, "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
    }
    if (text !== undefined) {
      let parsed: z.infer<typeof fileSchema> | undefined;
      try {
        parsed = fileSchema.parse(JSON.parse(text));
      } catch {
        log?.error("cache index unreadable; starting empty (files will be re-cached on demand)", { file: indexFile });
      }
      const now = Date.now();
      for (const [path, until] of Object.entries(parsed?.pins ?? {})) if (until > now && isSafeRepoPath(path)) idx.pins.set(path, until);
      for (const e of parsed?.entries ?? []) {
        try {
          const st = await stat(await realCacheFile(root, e.repoPath));
          if (st.isFile() && st.size === e.size) {
            idx.entries.set(e.repoPath, e);
            continue;
          }
        } catch {
          // fall through: missing or unsafe
        }
        log?.warn("cache entry dropped (file missing or changed)", { repoPath: e.repoPath });
      }
      await idx.persist();
    }
    return idx;
  }

  get(repoPath: string): CacheEntry | undefined {
    return this.entries.get(repoPath);
  }

  list(): CacheEntry[] {
    return [...this.entries.values()];
  }

  stats(): { files: number; bytes: number } {
    let bytes = 0;
    for (const e of this.entries.values()) bytes += e.size;
    return { files: this.entries.size, bytes };
  }

  async put(entry: CacheEntry): Promise<void> {
    const e = entrySchema.parse(entry);
    await this.serial(async () => {
      this.entries.set(e.repoPath, e);
      this.pendingDelete.delete(e.repoPath); // the new file replaced the one an old reader still holds
      this.memo.delete(e.repoPath);
      this.lastUsed.set(e.repoPath, Date.now());
      await this.persist();
    });
  }

  /** Remove from the index (stops serving immediately) and delete the file (once no reader holds it). */
  async remove(repoPath: string): Promise<void> {
    await this.serial(async () => {
      this.entries.delete(repoPath);
      this.memo.delete(repoPath);
      this.lastUsed.delete(repoPath);
      await this.persist();
      if ((this.refs.get(repoPath) ?? 0) > 0) {
        this.pendingDelete.add(repoPath);
        return;
      }
      await rmRetry(cacheAbsPath(this.root, repoPath));
    });
  }

  /** A reader (cache server download) starts using the file. Returns false if it is not indexed. */
  acquire(repoPath: string): boolean {
    if (!this.entries.has(repoPath)) return false;
    this.refs.set(repoPath, (this.refs.get(repoPath) ?? 0) + 1);
    this.lastUsed.set(repoPath, Date.now());
    return true;
  }

  /** The reader finished; a file removed meanwhile is deleted now. */
  async release(repoPath: string): Promise<void> {
    const n = (this.refs.get(repoPath) ?? 1) - 1;
    if (n > 0) {
      this.refs.set(repoPath, n);
      return;
    }
    this.refs.delete(repoPath);
    if (this.pendingDelete.delete(repoPath) && !this.entries.has(repoPath)) {
      await this.serial(() => rmRetry(cacheAbsPath(this.root, repoPath)));
    }
  }

  inUse(repoPath: string): boolean {
    return (this.refs.get(repoPath) ?? 0) > 0;
  }

  /** Mark a package as used now (LRU order for eviction). */
  touch(repoPath: string): void {
    if (this.entries.has(repoPath)) this.lastUsed.set(repoPath, Date.now());
  }

  /** Protect paths from eviction until `untilMs` (the expiry of a job that refers to them). */
  async pin(paths: readonly string[], untilMs: number): Promise<void> {
    if (!Number.isFinite(untilMs)) return;
    let dirty = false;
    for (const p of new Set(paths)) {
      if (!isSafeRepoPath(p)) continue;
      const cur = this.pins.get(p);
      if (cur !== undefined && cur >= untilMs) continue;
      this.pins.set(p, untilMs);
      if (cur === undefined || untilMs - cur > PIN_PERSIST_SLACK_MS) dirty = true;
    }
    if (dirty) await this.serial(() => this.persist());
  }

  pinnedUntil(repoPath: string): number | undefined {
    return this.pins.get(repoPath);
  }

  /**
   * LRU eviction of packages no unexpired job refers to and no PC is downloading, until the cache fits
   * maxBytes and the volume keeps minFreeBytes free (after adding needBytes).
   */
  async evict(o: EvictOptions): Promise<EvictResult> {
    for (const [p, until] of this.pins) if (until <= o.now) this.pins.delete(p);
    let bytes = this.stats().bytes;
    let free = await o.freeBytes();
    const over = () => (o.maxBytes !== null && bytes + o.needBytes > o.maxBytes) || (free !== null && free - o.needBytes < o.minFreeBytes);
    const removed: CacheEntry[] = [];
    if (!over()) return { removed, stillOver: false };
    const used = (e: CacheEntry) => this.lastUsed.get(e.repoPath) ?? (Date.parse(e.cachedAt) || 0);
    const candidates = this.list()
      .filter((e) => !this.pins.has(e.repoPath) && !this.inUse(e.repoPath))
      .sort((a, b) => used(a) - used(b));
    for (const e of candidates) {
      if (!over()) break;
      await this.remove(e.repoPath);
      removed.push(e);
      bytes -= e.size;
      if (free !== null) free += e.size;
    }
    return { removed, stillOver: over() };
  }

  /**
   * Re-hash the cached file and compare with the index (before every use by DEPLOY_PACKAGE).
   * Concurrent checks of the same file share one hash run; an unchanged file (same inode, size,
   * mtime) verified within the last minute is not re-read.
   */
  verify(repoPath: string): Promise<boolean> {
    const running = this.inflight.get(repoPath);
    if (running) return running;
    const p = this.doVerify(repoPath).finally(() => this.inflight.delete(repoPath));
    this.inflight.set(repoPath, p);
    return p;
  }

  private async doVerify(repoPath: string): Promise<boolean> {
    const e = this.entries.get(repoPath);
    if (!e) return false;
    let file: string;
    try {
      file = await realCacheFile(this.root, repoPath);
    } catch {
      return false;
    }
    const st = await stat(file);
    const m = this.memo.get(repoPath);
    if (m && m.size === st.size && m.mtimeMs === st.mtimeMs && m.ino === st.ino && Date.now() - m.at < VERIFY_TTL_MS) return true;
    const h = await hashFile(file);
    const ok = h.sha256 === e.sha256 && h.size === e.size;
    if (ok) this.memo.set(repoPath, { size: st.size, mtimeMs: st.mtimeMs, ino: st.ino, at: Date.now() });
    else this.memo.delete(repoPath);
    return ok;
  }

  private serial(fn: () => Promise<void>): Promise<void> {
    const p = this.chain.then(fn, fn);
    this.chain = p.catch(() => undefined);
    return p;
  }

  private async persist(): Promise<void> {
    const now = Date.now();
    const pins = Object.fromEntries([...this.pins].filter(([, until]) => until > now));
    const body = { v: 1 as const, entries: this.list(), pins };
    await writeFileAtomic(this.indexFile, `${JSON.stringify(body, null, 1)}\n`, 0o600);
  }
}
