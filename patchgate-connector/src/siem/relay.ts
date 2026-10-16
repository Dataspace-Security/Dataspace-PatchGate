import { readFile } from "node:fs/promises";
import { connect as tcpConnect, type Socket } from "node:net";
import { connect as tlsConnect } from "node:tls";
import { z } from "zod";
import type { PatchGateClient } from "../pg-client.ts";
import { backoffDelay, sleep, AbortedError } from "../util/backoff.ts";
import { writeFileAtomic } from "../util/fsx.ts";
import { errorMessage, type Logger } from "../util/log.ts";
import { formatSyslog, frameOctetCounting, type SiemTarget } from "./syslog.ts";

/**
 * Audit relay: pulls this bank's audit chain from PatchGate (GET /audit?after=seq) and forwards each
 * record as RFC 5424 over ONE persistent TLS connection to the bank SIEM. lastForwardedSeq is
 * persisted only after the batch was written and flushed to the socket, so a crash or connection
 * loss re-sends (at-least-once; the SIEM de-duplicates on seq+hash).
 */

const stateSchema = z.object({ lastForwardedSeq: z.string().regex(/^\d{1,24}$/) });
const SEQ_RE = /^\d{1,24}$/;

export class AuditPageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AuditPageError";
  }
}

type AuditPage = Awaited<ReturnType<PatchGateClient["getAudit"]>>;

/**
 * Integrity checks on one audit page before anything is forwarded (a compromised or buggy server must
 * not be able to make the relay skip records silently). The whole page is rejected, nothing is
 * forwarded and lastForwardedSeq does not move, when:
 *  - a seq is malformed, not above `after`, or the records are not strictly increasing (server order);
 *  - the page has more records than requested;
 *  - the page is short (fewer than `limit` records, i.e. "nothing more") yet the tenant's chain head
 *    is beyond its last record: records between them were withheld;
 *  - a record lies beyond the reported head.
 * seq is a platform-wide counter (gaps between one bank's records are normal), so gap size itself is
 * not checked; completeness is checked against the head instead.
 */
export function validateAuditPage(after: string, limit: number, page: AuditPage): AuditPage["records"] {
  const last = BigInt(after);
  let prev = last;
  if (page.records.length > limit) throw new AuditPageError(`audit page has ${page.records.length} records, ${limit} requested`);
  for (const r of page.records) {
    if (!SEQ_RE.test(r.seq)) throw new AuditPageError("audit record with malformed seq");
    const seq = BigInt(r.seq);
    if (seq <= prev) throw new AuditPageError(`audit seq not strictly increasing after ${prev} (got ${r.seq})`);
    prev = seq;
  }
  if (page.head) {
    if (!SEQ_RE.test(page.head.seq)) throw new AuditPageError("audit head with malformed seq");
    const head = BigInt(page.head.seq);
    if (prev > head) throw new AuditPageError(`audit record ${prev} lies beyond the chain head ${head}`);
    if (page.records.length < limit && head > prev) {
      throw new AuditPageError(`audit page ends at ${prev} with fewer than ${limit} records but the chain head is ${head}: records withheld`);
    }
  } else if (page.records.length > 0) {
    throw new AuditPageError("audit page has records but no chain head");
  }
  return page.records;
}

export interface SiemRelayOptions {
  pg: PatchGateClient;
  target: SiemTarget;
  ca?: string | Buffer;
  hostname: string;
  stateFile: string;
  pollIntervalMs: number;
  batchSize: number;
  connectTimeoutMs?: number;
  log: Logger;
}

export interface SiemStatus {
  configured: boolean;
  lastForwardedSeq: string | null;
  error: string | null;
}

export class SiemRelay {
  private lastSeq = "0";
  private error: string | null = null;
  private sock: Socket | undefined;
  private readonly abort = new AbortController();
  private loop: Promise<void> | undefined;

  constructor(private readonly opts: SiemRelayOptions) {}

  status(): SiemStatus {
    return { configured: true, lastForwardedSeq: this.lastSeq, error: this.error };
  }

  async start(): Promise<void> {
    try {
      const parsed = stateSchema.parse(JSON.parse(await readFile(this.opts.stateFile, "utf8")));
      this.lastSeq = parsed.lastForwardedSeq;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") this.opts.log.warn("SIEM relay state unreadable; starting from 0", { err });
    }
    this.loop = this.run();
  }

  async stop(): Promise<void> {
    this.abort.abort();
    await this.loop?.catch(() => undefined);
    this.sock?.destroy();
    this.sock = undefined;
  }

  /** One pull+forward round; returns the number of records forwarded. Exposed for tests. */
  async forwardOnce(): Promise<number> {
    const signal = this.abort.signal;
    const resp = await this.opts.pg.getAudit(this.lastSeq, this.opts.batchSize, signal);
    const records = validateAuditPage(this.lastSeq, this.opts.batchSize, resp);
    if (records.length === 0) return 0;

    const lines = records.map((r) =>
      formatSyslog({
        ts: new Date(r.ts),
        hostname: this.opts.hostname,
        msgId: "AUDIT",
        // Same structured data as PatchGate's own exporter: prevHash lets the SIEM run its chain-break rule
        // (fork / regression use seq + hash). Omitted only when an older server does not send it.
        sd: r.prevHash ? { seq: r.seq, hash: r.hash, prevHash: r.prevHash } : { seq: r.seq, hash: r.hash },
        msg: JSON.stringify({ actor: r.actor, action: r.action, entity: r.entity, entityId: r.entityId, payload: r.payload }),
      }),
    );
    const tail = records[records.length - 1]!;
    lines.push(
      formatSyslog({
        ts: new Date(),
        hostname: this.opts.hostname,
        msgId: "ANCHOR",
        sd: { seq: tail.seq, hash: tail.hash, count: String(records.length), headSeq: resp.head?.seq ?? "-", headHash: resp.head?.hash ?? "-" },
        msg: "audit chain relay checkpoint",
      }),
    );

    const sock = await this.connection();
    await new Promise<void>((resolve, reject) => {
      const onError = (err: Error) => reject(err);
      sock.once("error", onError);
      sock.write(lines.map(frameOctetCounting).join(""), "utf8", (err) => {
        sock.off("error", onError);
        if (err) reject(err);
        else resolve();
      });
    });
    // flushed to the kernel: now (and only now) advance the persisted position
    await writeFileAtomic(this.opts.stateFile, JSON.stringify({ lastForwardedSeq: tail.seq }), 0o600);
    this.lastSeq = tail.seq;
    return records.length;
  }

  private async run(): Promise<void> {
    let attempt = 0;
    const signal = this.abort.signal;
    while (!signal.aborted) {
      try {
        const n = await this.forwardOnce();
        this.error = null;
        attempt = 0;
        if (n < this.opts.batchSize) await sleep(this.opts.pollIntervalMs, signal);
      } catch (err) {
        if (err instanceof AbortedError || signal.aborted) return;
        this.error = errorMessage(err).slice(0, 500);
        if (err instanceof AuditPageError) this.opts.log.error("audit page REJECTED (integrity check); nothing forwarded, position unchanged", { security: true, error: this.error, lastForwardedSeq: this.lastSeq });
        else this.opts.log.warn("SIEM relay error; will retry", { error: this.error, lastForwardedSeq: this.lastSeq });
        this.sock?.destroy();
        this.sock = undefined;
        try {
          await sleep(backoffDelay(attempt++, { baseMs: 1000, maxMs: 60_000 }), signal);
        } catch {
          return;
        }
      }
    }
  }

  private connection(): Promise<Socket> {
    const existing = this.sock;
    if (existing && !existing.destroyed && existing.writable) return Promise.resolve(existing);
    this.sock = undefined;
    const { target, ca } = this.opts;
    return new Promise<Socket>((resolve, reject) => {
      const timeoutMs = this.opts.connectTimeoutMs ?? 10_000;
      let settled = false;
      const done = (err?: Error) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (err) {
          s.destroy();
          reject(err);
        } else {
          s.off("error", done);
          // a peer close or error marks the connection dead; the next batch reconnects
          s.on("error", () => s.destroy());
          s.on("end", () => s.destroy());
          s.setKeepAlive(true, 30_000);
          this.sock = s;
          resolve(s);
        }
      };
      const s: Socket =
        target.protocol === "tls"
          ? tlsConnect({ host: target.host, port: target.port, servername: target.host, ca, rejectUnauthorized: true, minVersion: "TLSv1.2" }, () => done())
          : tcpConnect({ host: target.host, port: target.port }, () => done());
      s.once("error", done);
      const timer = setTimeout(() => done(new Error("SIEM connect timed out")), timeoutMs);
    });
  }
}
