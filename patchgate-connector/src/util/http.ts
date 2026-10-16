import { Agent as HttpAgent, request as httpReq, type IncomingHttpHeaders, type IncomingMessage } from "node:http";
import { Agent as HttpsAgent, request as httpsReq } from "node:https";

/**
 * Minimal HTTP(S) client on node built-ins: explicit CA pinning per destination, hard timeouts,
 * response size caps, never follows redirects (so credentials are never forwarded elsewhere).
 */

export class HttpNetworkError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "HttpNetworkError";
  }
}

export interface HttpRequestOptions {
  method: string;
  url: URL;
  headers?: Record<string, string>;
  body?: string | Buffer;
  /** Total time for request + full response (buffered mode) or idle socket time (stream mode). */
  timeoutMs: number;
  agent?: HttpAgent | HttpsAgent;
  signal?: AbortSignal;
  maxResponseBytes?: number;
}

export interface HttpResponse {
  status: number;
  headers: IncomingHttpHeaders;
  body: Buffer;
}

export interface HttpAgentOptions {
  ca?: string | Buffer;
  keepAlive?: boolean;
  maxSockets?: number;
}

export function createAgent(url: URL, opts: HttpAgentOptions = {}): HttpAgent | HttpsAgent {
  const common = { keepAlive: opts.keepAlive ?? true, maxSockets: opts.maxSockets ?? 32 };
  if (url.protocol === "https:") {
    return new HttpsAgent({ ...common, ca: opts.ca, rejectUnauthorized: true, minVersion: "TLSv1.2" });
  }
  return new HttpAgent(common);
}

function start(opts: HttpRequestOptions): Promise<{ res: IncomingMessage; abort: (err: Error) => void }> {
  return new Promise((resolve, reject) => {
    if (opts.url.protocol !== "https:" && opts.url.protocol !== "http:") {
      reject(new HttpNetworkError(`unsupported protocol ${opts.url.protocol}`));
      return;
    }
    if (opts.signal?.aborted) {
      reject(new HttpNetworkError("request aborted"));
      return;
    }
    const body = opts.body === undefined ? undefined : Buffer.isBuffer(opts.body) ? opts.body : Buffer.from(opts.body, "utf8");
    const headers: Record<string, string> = { ...opts.headers };
    if (body) headers["content-length"] = String(body.length);
    const fn = opts.url.protocol === "https:" ? httpsReq : httpReq;
    const req = fn(opts.url, { method: opts.method, headers, agent: opts.agent });
    const abort = (err: Error) => req.destroy(err);
    const onAbort = () => abort(new HttpNetworkError("request aborted"));
    opts.signal?.addEventListener("abort", onAbort, { once: true });
    req.on("close", () => opts.signal?.removeEventListener("abort", onAbort));
    req.on("error", (err) => reject(err instanceof HttpNetworkError ? err : new HttpNetworkError(err.message)));
    req.on("response", (res) => resolve({ res, abort }));
    req.end(body);
  });
}

/** Buffered request. Rejects with HttpNetworkError on transport problems; HTTP status is returned as-is. */
export async function httpRequest(opts: HttpRequestOptions): Promise<HttpResponse> {
  const max = opts.maxResponseBytes ?? 32 * 1024 * 1024;
  let timer: NodeJS.Timeout | undefined;
  // The local controller also tears down a request that is still waiting for response headers.
  const local = new AbortController();
  const signal = opts.signal ? AbortSignal.any([opts.signal, local.signal]) : local.signal;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      local.abort();
      reject(new HttpNetworkError(`timeout after ${opts.timeoutMs} ms`));
    }, opts.timeoutMs);
  });
  const work = (async () => {
    const { res, abort } = await start({ ...opts, signal });
    const onAbort = () => abort(new HttpNetworkError("request aborted"));
    signal.addEventListener("abort", onAbort, { once: true });
    res.once("close", () => signal.removeEventListener("abort", onAbort));
    const chunks: Buffer[] = [];
    let size = 0;
    try {
      for await (const chunk of res) {
        const buf = chunk as Buffer;
        size += buf.length;
        if (size > max) {
          abort(new HttpNetworkError("response too large"));
          throw new HttpNetworkError("response too large");
        }
        chunks.push(buf);
      }
    } catch (err) {
      throw err instanceof HttpNetworkError ? err : new HttpNetworkError((err as Error).message);
    }
    return { status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks) };
  })();
  try {
    return await Promise.race([work, timeout]);
  } finally {
    clearTimeout(timer);
    work.catch(() => undefined);
  }
}

/**
 * Idle timeout for a streamed response, scoped to THIS response. Keep-alive sockets are reused by later
 * requests: a socket-level timeout + listener that is never removed would fire on the next request
 * (stale abort) and pile up 'timeout' listeners (MaxListenersExceededWarning). Both are removed as soon
 * as the response ends or closes.
 */
export function armIdleTimeout(res: IncomingMessage, timeoutMs: number, onIdle: () => void): void {
  const sock = res.socket;
  if (!sock) return;
  const prev = sock.timeout ?? 0;
  const handler = () => onIdle();
  let armed = true;
  const disarm = () => {
    if (!armed) return;
    armed = false;
    sock.off("timeout", handler);
    if (!sock.destroyed) sock.setTimeout(prev);
  };
  sock.setTimeout(timeoutMs);
  sock.on("timeout", handler);
  res.once("end", disarm);
  res.once("close", disarm);
  res.once("error", disarm);
}

/** Streaming request: resolves with the response once headers arrive; idle timeout applies until it ends. */
export async function httpRequestStream(opts: HttpRequestOptions): Promise<{ res: IncomingMessage; abort: (err: Error) => void }> {
  let timer: NodeJS.Timeout | undefined;
  const local = new AbortController();
  const headerTimeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      local.abort(); // tears down a request still waiting for headers
      reject(new HttpNetworkError(`timeout after ${opts.timeoutMs} ms`));
    }, opts.timeoutMs);
  });
  const started = start({ ...opts, signal: opts.signal ? AbortSignal.any([opts.signal, local.signal]) : local.signal });
  try {
    const out = await Promise.race([started, headerTimeout]);
    armIdleTimeout(out.res, opts.timeoutMs, () => out.abort(new HttpNetworkError("download stalled")));
    return out;
  } catch (err) {
    started.then((s) => s.abort(new HttpNetworkError("timeout")), () => undefined);
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

export function headerValue(h: IncomingHttpHeaders, name: string): string | undefined {
  const v = h[name.toLowerCase()];
  return Array.isArray(v) ? v[0] : v;
}
