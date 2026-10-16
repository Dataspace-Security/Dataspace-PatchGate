import { createReadStream } from "node:fs";
import { stat } from "node:fs/promises";
import { createServer as createHttpServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import type { AddressInfo } from "node:net";
import { Transform, type TransformCallback } from "node:stream";
import { pipeline } from "node:stream/promises";
import type { Logger } from "../util/log.ts";
import type { TokenBucket } from "../util/token-bucket.ts";
import type { CacheIndex } from "./cache-index.ts";
import { isSafeRepoPath, realCacheFile } from "./paths.ts";

/**
 * Package cache server for PCs inside the bank LAN.
 *  - serves ONLY files present in the verified cache index (no listing, no traversal, realpath check)
 *  - GET/HEAD only, single-range support
 *  - NETWORK PROTECTION: global concurrent-download cap, per-client-IP cap, one token bucket shared by
 *    all downloads (bandwidth limit, live-updatable), 503 + Retry-After when saturated
 *  - /healthz for monitoring
 */

export interface CacheServerOptions {
  root: string;
  index: CacheIndex;
  /** URL path prefix from cache.baseUrl, e.g. "/repo" or "". */
  prefix: string;
  host: string;
  port: number;
  tls?: { cert: string | Buffer; key: string | Buffer };
  maxConcurrentDownloads: number;
  perClientConcurrency: number;
  retryAfterSec: number;
  bucket: TokenBucket;
  log: Logger;
}

export interface CacheServerStats {
  activeDownloads: number;
  servedTotal: number;
  rejectedBusy: number;
  bytesSent: number;
}

const CHUNK = 64 * 1024;

class Throttle extends Transform {
  constructor(
    private readonly bucket: TokenBucket,
    private readonly onBytes: (n: number) => void,
  ) {
    super({ highWaterMark: CHUNK });
  }
  override _transform(chunk: Buffer, _enc: BufferEncoding, cb: TransformCallback): void {
    this.bucket.take(chunk.length).then(
      () => {
        this.onBytes(chunk.length);
        cb(null, chunk);
      },
      (err: unknown) => cb(err as Error),
    );
  }
}

type Range = { start: number; end: number } | "invalid" | null;

export function parseRange(header: string | undefined, size: number): Range {
  if (!header) return null;
  const m = /^bytes=(\d*)-(\d*)$/.exec(header.trim());
  if (!m || (m[1] === "" && m[2] === "")) return header.includes(",") ? null : "invalid"; // multi-range: serve whole file
  let start: number;
  let end: number;
  if (m[1] === "") {
    const suffix = Number(m[2]);
    if (suffix === 0) return "invalid";
    start = Math.max(0, size - suffix);
    end = size - 1;
  } else {
    start = Number(m[1]);
    end = m[2] === "" ? size - 1 : Math.min(Number(m[2]), size - 1);
  }
  if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start > end || start >= size) return "invalid";
  return { start, end };
}

export class CacheServer {
  private server: Server | undefined;
  private active = 0;
  private readonly perIp = new Map<string, number>();
  private readonly counters = { servedTotal: 0, rejectedBusy: 0, bytesSent: 0 };

  constructor(private readonly opts: CacheServerOptions) {}

  stats(): CacheServerStats {
    return { activeDownloads: this.active, ...this.counters };
  }

  async start(): Promise<AddressInfo> {
    const handler = (req: IncomingMessage, res: ServerResponse) => {
      this.handle(req, res).catch((err: unknown) => {
        this.opts.log.error("cache server request failed", { err });
        if (!res.headersSent) this.send(res, 500, "internal error");
        else res.destroy();
      });
    };
    const server = this.opts.tls
      ? createHttpsServer({ cert: this.opts.tls.cert, key: this.opts.tls.key, minVersion: "TLSv1.2" }, handler)
      : createHttpServer(handler);
    server.headersTimeout = 10_000;
    server.requestTimeout = 30_000;
    server.keepAliveTimeout = 5_000;
    server.maxHeadersCount = 50;
    server.timeout = 120_000; // stalled client sockets are closed and free their slot
    server.maxConnections = this.opts.maxConcurrentDownloads * 4 + 100;
    this.server = server;
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(this.opts.port, this.opts.host, () => {
        server.off("error", reject);
        resolve();
      });
    });
    return server.address() as AddressInfo;
  }

  async stop(): Promise<void> {
    const s = this.server;
    if (!s) return;
    this.server = undefined;
    await new Promise<void>((resolve) => {
      s.close(() => resolve());
      s.closeAllConnections();
    });
  }

  private send(res: ServerResponse, status: number, text: string, extra: Record<string, string> = {}): void {
    const body = `${text}\n`;
    res.writeHead(status, {
      "content-type": "text/plain; charset=utf-8",
      "content-length": String(Buffer.byteLength(body)),
      "x-content-type-options": "nosniff",
      "cache-control": "no-store",
      ...extra,
    });
    res.end(res.req.method === "HEAD" ? undefined : body);
  }

  private async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const method = req.method ?? "";
    const rawUrl = req.url ?? "";
    const path = rawUrl.split("?")[0] ?? "";

    if (method !== "GET" && method !== "HEAD") {
      this.send(res, 405, "method not allowed", { allow: "GET, HEAD" });
      return;
    }
    if (path === "/healthz") {
      const body = JSON.stringify({ status: "ok", activeDownloads: this.active, maxConcurrentDownloads: this.opts.maxConcurrentDownloads, files: this.opts.index.stats().files });
      res.writeHead(200, { "content-type": "application/json", "content-length": String(Buffer.byteLength(body)), "cache-control": "no-store" });
      res.end(method === "HEAD" ? undefined : body);
      return;
    }

    // Only "<prefix>/<repoPath>" with a safe, indexed repoPath. Anything else (encoded chars,
    // backslashes, dot segments, directories, unknown files) is a uniform 404.
    const prefix = `${this.opts.prefix}/`;
    if (!path.startsWith(prefix)) return this.send(res, 404, "not found");
    const rel = path.slice(prefix.length);
    if (!isSafeRepoPath(rel)) return this.send(res, 404, "not found");
    const entry = this.opts.index.get(rel);
    if (!entry) return this.send(res, 404, "not found");

    let file: string;
    let size: number;
    try {
      file = await realCacheFile(this.opts.root, rel);
      const st = await stat(file);
      if (!st.isFile() || st.size !== entry.size) throw new Error("cached file changed on disk");
      size = st.size;
    } catch (err) {
      this.opts.log.error("indexed cache file unusable", { repoPath: rel, err });
      return this.send(res, 404, "not found");
    }

    const range = parseRange(typeof req.headers.range === "string" ? req.headers.range : undefined, size);
    if (range === "invalid") return this.send(res, 416, "range not satisfiable", { "content-range": `bytes */${size}` });

    const headers: Record<string, string> = {
      "content-type": "application/octet-stream",
      "accept-ranges": "bytes",
      etag: `"${entry.sha256}"`,
      "x-content-sha256": entry.sha256,
      "cache-control": "private, max-age=0",
      "x-content-type-options": "nosniff",
    };
    if (method === "HEAD") {
      res.writeHead(200, { ...headers, "content-length": String(size) });
      res.end();
      return;
    }

    // ---- admission control (network protection) ----
    const ip = req.socket.remoteAddress ?? "unknown";
    const ipActive = this.perIp.get(ip) ?? 0;
    if (this.active >= this.opts.maxConcurrentDownloads || ipActive >= this.opts.perClientConcurrency) {
      this.counters.rejectedBusy++;
      return this.send(res, 503, "busy, retry later", { "retry-after": String(this.opts.retryAfterSec) });
    }
    this.active++;
    this.perIp.set(ip, ipActive + 1);
    let released = false;
    const release = () => {
      if (released) return;
      released = true;
      this.active--;
      const n = (this.perIp.get(ip) ?? 1) - 1;
      if (n <= 0) this.perIp.delete(ip);
      else this.perIp.set(ip, n);
    };
    res.on("close", release);
    // Refcount: the index never deletes a file while a PC is downloading it (eviction, re-check failure).
    if (!this.opts.index.acquire(rel)) {
      release();
      return this.send(res, 404, "not found");
    }

    const start = range ? range.start : 0;
    const end = range ? range.end : size - 1;
    if (range) {
      res.writeHead(206, { ...headers, "content-length": String(end - start + 1), "content-range": `bytes ${start}-${end}/${size}` });
    } else {
      res.writeHead(200, { ...headers, "content-length": String(size) });
    }
    try {
      await pipeline(
        createReadStream(file, { start, end, highWaterMark: CHUNK }),
        new Throttle(this.opts.bucket, (n) => {
          this.counters.bytesSent += n;
        }),
        res,
      );
      this.counters.servedTotal++;
    } catch {
      // client went away mid-download; slot is released by the close handler
      res.destroy();
    } finally {
      release();
      await this.opts.index.release(rel).catch((err: unknown) => this.opts.log.warn("deferred delete of an evicted cache file failed", { repoPath: rel, err }));
    }
  }
}
