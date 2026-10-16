import { open, readFile, stat, type FileHandle } from "node:fs/promises";
import { z } from "zod";
import { jobResultSchema, MAX_CLOCK_SKEW_MS, type JobResult } from "./protocol.ts";
import { writeFileAtomic } from "./util/fsx.ts";
import type { Logger } from "./util/log.ts";

/**
 * Append-only JSONL journal of job execution, fsync'd per record. Gives:
 *  - idempotency: a re-delivered job whose result is known is never executed twice (install jobs);
 *  - durability: results not yet acknowledged by PatchGate are re-posted after a restart;
 *  - crash safety: a job "started" but never "done" is known to have been interrupted.
 *
 * Bounded size (10k-PC sites post MBs of COLLECT pages every day):
 *  - full result bodies are held only while UNPOSTED; once PatchGate acknowledged a result only a small
 *    dedupe stub stays (id, type, ok/retryable/outcomeUnknown, timestamps, job expiry);
 *  - read-only results (SYNC_AGENTS/SCAN/COLLECT/WU_SCAN) are never written with their body at all:
 *    after a restart a re-delivered read-only job simply runs again (safe);
 *  - stubs are dropped once the job's signed expiry has passed (it can no longer be accepted) or after
 *    the retention period; the file is compacted at open and at runtime when it grows, with a size cap.
 */

const jobIdSchema = z.string().regex(/^[A-Za-z0-9_-]{1,64}$/);
// Job type as received (rejected jobs may carry an unknown type, so this is not the JobType enum).
const jobTypeSchema = z.string().regex(/^[A-Z_]{1,32}$/);
const isoSchema = z.string().max(40);

const recordSchema = z.discriminatedUnion("t", [
  z.object({ t: z.literal("start"), jobId: jobIdSchema, type: jobTypeSchema, at: isoSchema, exp: isoSchema.optional() }),
  z.object({
    t: z.literal("done"),
    jobId: jobIdSchema,
    type: jobTypeSchema,
    at: isoSchema,
    exp: isoSchema.optional(),
    /** Full body: only while unposted, never for read-only jobs. */
    result: jobResultSchema.optional(),
    /** Stub fields (always written by this version; derived from `result` for older records). */
    ok: z.boolean().optional(),
    retryable: z.boolean().optional(),
    outcomeUnknown: z.boolean().optional(),
  }),
  z.object({ t: z.literal("posted"), jobId: jobIdSchema, at: isoSchema, outcome: z.string().max(32) }),
]);
type JournalRecord = z.infer<typeof recordSchema>;

export interface ResultSummary {
  ok: boolean;
  retryable?: boolean;
  outcomeUnknown?: boolean;
}

export interface JobState {
  jobId: string;
  type: string;
  startedAt?: string;
  doneAt?: string;
  /** Full result body; present only while the result is unposted (and never for read-only jobs). */
  result?: JobResult;
  /** Outcome summary; kept after the body was dropped. */
  summary?: ResultSummary;
  postedAt?: string;
  postOutcome?: string;
  /** The signed job's expiresAt (ISO), when known. */
  expiresAt?: string;
}

export interface JournalOptions {
  retentionDays: number;
  /** Size cap of the journal file; compaction runs when it grows past min(cap, 2 × last compacted size). */
  maxBytes?: number;
  now?: () => number;
  log?: Logger;
}

export interface MarkDoneOptions {
  /** Write the full body (false for read-only jobs). Default true. */
  keepBody?: boolean;
  expiresAt?: string;
}

const DEFAULT_MAX_BYTES = 64 * 1024 * 1024;
const MIN_COMPACT_BYTES = 1024 * 1024;
/** Stubs outlive the job's expiry by this much (clock skew between us and PatchGate + margin). */
const EXPIRY_GRACE_MS = MAX_CLOCK_SKEW_MS + 3_600_000;

export const summarize = (r: JobResult): ResultSummary =>
  r.ok ? { ok: true } : { ok: false, retryable: r.retryable, ...(r.outcomeUnknown ? { outcomeUnknown: true } : {}) };

export class Journal {
  private chain: Promise<void> = Promise.resolve();
  private closed = false;
  private fileBytes = 0;
  private compactAt = MIN_COMPACT_BYTES;
  readonly stats = { compactions: 0, evicted: 0 };

  private constructor(
    private readonly path: string,
    private readonly states: Map<string, JobState>,
    private fh: FileHandle,
    readonly skippedLines: number,
    private readonly opts: JournalOptions,
  ) {}

  static async open(path: string, opts: JournalOptions): Promise<Journal> {
    let text = "";
    try {
      text = await readFile(path, "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
    }
    const states = new Map<string, JobState>();
    let skipped = 0;
    for (const line of text.split("\n")) {
      if (!line.trim()) continue;
      let rec: JournalRecord;
      try {
        rec = recordSchema.parse(JSON.parse(line));
      } catch {
        skipped++; // e.g. a torn last line after a power cut
        continue;
      }
      Journal.apply(states, rec);
    }
    text = "";
    const j = new Journal(path, states, undefined as unknown as FileHandle, skipped, opts);
    await j.rewrite();
    return j;
  }

  private static apply(states: Map<string, JobState>, rec: JournalRecord): void {
    const prev = states.get(rec.jobId);
    if (rec.t === "start") {
      states.set(rec.jobId, { ...prev, jobId: rec.jobId, type: rec.type, startedAt: rec.at, expiresAt: rec.exp ?? prev?.expiresAt });
    } else if (rec.t === "done") {
      // first recorded body wins (mirrors the server's rule); a read-only stub may be replaced by a re-run
      if (prev?.result) return;
      const summary: ResultSummary = rec.result ? summarize(rec.result) : { ok: rec.ok ?? false, retryable: rec.retryable, outcomeUnknown: rec.outcomeUnknown };
      // A "done" after a "posted" is a re-run of a read-only job: its new result is unposted again.
      // (Compaction writes a posted job as done-stub followed by posted, so this never loses a post.)
      states.set(rec.jobId, {
        ...prev,
        jobId: rec.jobId,
        type: rec.type,
        doneAt: rec.at,
        result: rec.result,
        summary,
        expiresAt: rec.exp ?? prev?.expiresAt,
        postedAt: undefined,
        postOutcome: undefined,
      });
    } else if (prev) {
      // acknowledged: from now on only the stub is kept
      const { result: _body, ...stub } = prev;
      states.set(rec.jobId, { ...stub, postedAt: rec.at, postOutcome: rec.outcome });
    }
  }

  get file(): string {
    return this.path;
  }

  get(jobId: string): JobState | undefined {
    const s = this.states.get(jobId);
    return s ? { ...s } : undefined;
  }

  /** Results recorded with a body but not yet acknowledged by PatchGate. */
  unposted(): JobState[] {
    return [...this.states.values()].filter((s) => s.result && !s.postedAt).map((s) => ({ ...s }));
  }

  get size(): number {
    return this.states.size;
  }

  /** Current journal file size in bytes. */
  get bytes(): number {
    return this.fileBytes;
  }

  markStarted(jobId: string, type: string, expiresAt?: string): Promise<void> {
    return this.append({ t: "start", jobId, type, at: new Date().toISOString(), ...(expiresAt ? { exp: expiresAt } : {}) });
  }

  /** Records the result; returns the result that is authoritative (an earlier body if one exists). */
  async markDone(jobId: string, type: string, result: JobResult, o: MarkDoneOptions = {}): Promise<JobResult> {
    const existing = this.states.get(jobId)?.result;
    if (existing) return existing;
    const keepBody = o.keepBody ?? true;
    await this.append({
      t: "done",
      jobId,
      type,
      at: new Date().toISOString(),
      ...(o.expiresAt ? { exp: o.expiresAt } : {}),
      ...(keepBody ? { result } : {}),
      ...summarize(result),
    });
    return result;
  }

  markPosted(jobId: string, outcome: string): Promise<void> {
    return this.append({ t: "posted", jobId, at: new Date().toISOString(), outcome });
  }

  /** Compact now (normally automatic). */
  compact(): Promise<void> {
    return this.serial(() => this.rewrite());
  }

  private serial(fn: () => Promise<void>): Promise<void> {
    const p = this.chain.then(fn, fn);
    this.chain = p.catch(() => undefined);
    return p;
  }

  private append(rec: JournalRecord): Promise<void> {
    const parsed = recordSchema.parse(rec);
    return this.serial(async () => {
      if (this.closed) throw new Error("journal is closed");
      const line = `${JSON.stringify(parsed)}\n`;
      await this.fh.write(line);
      await this.fh.datasync();
      this.fileBytes += Buffer.byteLength(line);
      Journal.apply(this.states, parsed);
      if (this.fileBytes > this.compactAt) await this.rewrite();
    });
  }

  private get maxBytes(): number {
    return this.opts.maxBytes ?? DEFAULT_MAX_BYTES;
  }

  /** Drop what is no longer needed, enforce the size cap, rewrite the file atomically, reopen for append. */
  private async rewrite(): Promise<void> {
    const now = (this.opts.now ?? Date.now)();
    const cutoff = now - this.opts.retentionDays * 86_400_000;
    for (const [id, s] of this.states) {
      if (s.result && !s.postedAt) continue; // undelivered result: always kept
      const expired = s.expiresAt !== undefined && Date.parse(s.expiresAt) + EXPIRY_GRACE_MS < now;
      const last = Date.parse(s.postedAt ?? s.doneAt ?? s.startedAt ?? "") || now;
      if (expired || last < cutoff) this.states.delete(id);
    }
    let lines = this.serialize();
    let bytes = lines.reduce((n, l) => n + Buffer.byteLength(l) + 1, 0);
    if (bytes > this.maxBytes) {
      // Over the cap: evict the oldest acknowledged stubs (never an undelivered result).
      const victims = [...this.states.values()].filter((s) => s.postedAt).sort((a, b) => Date.parse(a.postedAt ?? "") - Date.parse(b.postedAt ?? ""));
      let evicted = 0;
      for (const v of victims) {
        if (bytes <= this.maxBytes * 0.8) break;
        bytes -= this.lineBytes(v);
        this.states.delete(v.jobId);
        evicted++;
      }
      this.stats.evicted += evicted;
      this.opts.log?.warn("journal over its size cap; oldest acknowledged entries evicted", { evicted, maxBytes: this.maxBytes });
      lines = this.serialize();
      bytes = lines.reduce((n, l) => n + Buffer.byteLength(l) + 1, 0);
    }
    if (this.fh) {
      await this.fh.close(); // Windows: never rename over a file that is still open
    }
    await writeFileAtomic(this.path, lines.length ? `${lines.join("\n")}\n` : "", 0o600);
    this.fh = await open(this.path, "a", 0o600);
    this.fileBytes = (await stat(this.path)).size;
    this.compactAt = Math.min(this.maxBytes, Math.max(MIN_COMPACT_BYTES, this.fileBytes * 2));
    this.stats.compactions++;
  }

  private lineBytes(s: JobState): number {
    return Journal.lines(s).reduce((n, l) => n + Buffer.byteLength(l) + 1, 0);
  }

  private serialize(): string[] {
    const out: string[] = [];
    for (const s of this.states.values()) out.push(...Journal.lines(s));
    return out;
  }

  private static lines(s: JobState): string[] {
    const out: string[] = [];
    const exp = s.expiresAt ? { exp: s.expiresAt } : {};
    if (s.startedAt && !s.doneAt) out.push(JSON.stringify({ t: "start", jobId: s.jobId, type: s.type, at: s.startedAt, ...exp }));
    if (s.doneAt) {
      const body = s.result && !s.postedAt ? { result: s.result } : {};
      out.push(JSON.stringify({ t: "done", jobId: s.jobId, type: s.type, at: s.doneAt, ...exp, ...body, ...(s.summary ?? { ok: false }) }));
    }
    if (s.postedAt) out.push(JSON.stringify({ t: "posted", jobId: s.jobId, at: s.postedAt, outcome: s.postOutcome ?? "accepted" }));
    return out;
  }

  async close(): Promise<void> {
    await this.chain;
    if (this.closed) return;
    this.closed = true;
    await this.fh.close();
  }
}
