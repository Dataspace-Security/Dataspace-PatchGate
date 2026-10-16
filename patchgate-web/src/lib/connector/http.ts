import "server-only";
import { unstable_rethrow } from "next/navigation";
import { log } from "@/lib/log";
import { authenticateConnector, connectorMayUpload, pathWithQueryOf, type AuthedConnector } from "./auth";
import { ConnectorApiError, ConnectorAuthError } from "./errors";
import { HEADERS } from "./protocol";

/** Bodies above this size are only read for a known, ACTIVE connector. */
const PREFLIGHT_ABOVE_BYTES = 64 * 1024;

/**
 * Route plumbing for /api/connector/v1/**: capped raw body, signed-request authentication and the
 * plain-JSON error contract the connector understands ({ error } + status, Retry-After where useful).
 * Response bodies are protocol objects (not the browser API envelope).
 */

const NO_STORE = { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" } as const;

export function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return Response.json(body, { status, headers: { ...NO_STORE, ...headers } });
}

export function noContent(): Response {
  return new Response(null, { status: 204, headers: NO_STORE });
}

/** Read the raw request body, refusing more than `limit` bytes (checked before and while reading). */
export async function readBodyCapped(req: Request, limit: number): Promise<Uint8Array> {
  const declared = req.headers.get("content-length");
  if (declared !== null && (!/^\d{1,12}$/.test(declared) || Number(declared) > limit)) {
    throw new ConnectorApiError(413, "request body too large");
  }
  if (!req.body) return new Uint8Array(0);
  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > limit) {
      await reader.cancel().catch(() => undefined);
      throw new ConnectorApiError(413, "request body too large");
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.byteLength;
  }
  return out;
}

/** Parse a JSON body; malformed JSON is a 400 (the connector does not retry it). */
export function parseJsonBody(body: Uint8Array): unknown {
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(body));
  } catch {
    throw new ConnectorApiError(400, "body is not valid JSON");
  }
}

export interface ConnectorRequestContext {
  connector: AuthedConnector;
  body: Uint8Array;
  url: URL;
}

/** Map failures to the connector's status contract; internals never leak. */
export function errorResponse(err: unknown, route: string): Response {
  unstable_rethrow(err);
  if (err instanceof ConnectorAuthError) {
    log.warn("connector.auth.rejected", { route, reason: err.reason, status: err.status });
    return json({ error: err.message }, err.status);
  }
  if (err instanceof ConnectorApiError) {
    const headers: Record<string, string> = err.retryAfterSec !== undefined ? { "Retry-After": String(err.retryAfterSec) } : {};
    return json({ error: err.message }, err.status, headers);
  }
  log.error("connector.api.unhandled", { route, err });
  return json({ error: "internal error" }, 503, { "Retry-After": "30" });
}

/** Authenticated connector route: body cap → signature/nonce/timestamp → handler. */
export async function withConnector(
  req: Request,
  route: string,
  bodyLimit: number,
  handler: (ctx: ConnectorRequestContext) => Promise<Response>,
): Promise<Response> {
  try {
    if (bodyLimit > PREFLIGHT_ABOVE_BYTES && !(await connectorMayUpload(req.headers.get(HEADERS.connector) ?? ""))) {
      throw new ConnectorAuthError("unknown or inactive connector (before reading the body)");
    }
    const body = await readBodyCapped(req, bodyLimit);
    const connector = await authenticateConnector({ method: req.method, pathWithQuery: pathWithQueryOf(req), headers: req.headers, body });
    return await handler({ connector, body, url: new URL(req.url) });
  } catch (err: unknown) {
    return errorResponse(err, route);
  }
}
