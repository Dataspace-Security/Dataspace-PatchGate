import "server-only";
import { createReadStream } from "node:fs";
import { Readable } from "node:stream";
import { env } from "@/lib/env";
import { log } from "@/lib/log";
import { clientIp } from "@/lib/ratelimit/limiter";
import { connectorServerUrl } from "./admin";
import { FORBIDDEN_BODY, auditBundleDownload, authorizeBundleAccess } from "./bundle-access";
import { BundleError, type ByteRange, SIG_FILE, SUMS_FILE, bundleConfig, contentTypeOf, listedFile, parseRange, readSums, resolveBundle, signatureFile, siteScript } from "./site-bundle";

/**
 * Response building for the one-line site install (route handlers under src/app/install/** stay thin).
 * Machine traffic: plain-text bodies, `Cache-Control: no-store`, never a redirect to /login (src/proxy.ts).
 */

const NO_STORE = { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" } as const;

const text = (status: number, body: string, extra: Record<string, string> = {}) =>
  new Response(body, { status, headers: { "Content-Type": "text/plain; charset=utf-8", ...NO_STORE, ...extra } });

function errorResponse(err: unknown, where: string): Response {
  if (err instanceof BundleError) return text(err.status, `${err.message}\n`);
  log.error("install.failed", { where, error: err instanceof Error ? err.message : String(err) });
  return text(500, "internal error\n");
}

/** GET /install/site.sh — public; the script holds no secret. */
export async function siteScriptResponse(): Promise<Response> {
  try {
    const { body, version } = await siteScript(bundleConfig(), connectorServerUrl());
    return new Response(body, { status: 200, headers: { "Content-Type": "text/x-shellscript; charset=utf-8", "X-PatchGate-Bundle-Version": version, ...NO_STORE } });
  } catch (err: unknown) {
    return errorResponse(err, "site.sh");
  }
}

/** GET /install/bundle/<version|latest>/<SHA256SUMS | SHA256SUMS.sig | file listed in SHA256SUMS>. */
export async function bundleFileResponse(req: Request, versionParam: string, fileParam: string): Promise<Response> {
  const ip = clientIp(req.headers, env().TRUST_PROXY_HOPS);
  try {
    const cfg = bundleConfig();
    if (!cfg) return text(404, "site bundles not configured\n");
    const access = await authorizeBundleAccess(req.headers.get("authorization"), ip);
    if (!access.ok) {
      return access.status === 429 ? text(429, "Too many requests\n", { "Retry-After": String(access.retryAfterSec ?? 60) }) : text(403, FORBIDDEN_BODY);
    }
    const bundle = await resolveBundle(cfg, versionParam);
    if (fileParam === SUMS_FILE) {
      const { text: body } = await readSums(bundle);
      return text(200, body, { "X-PatchGate-Bundle-Version": bundle.version });
    }
    if (fileParam === SIG_FILE) {
      const sig = await signatureFile(bundle);
      return streamFile(sig.path, sig.size, parseRange(req.headers.get("range"), sig.size), SIG_FILE, "application/octet-stream");
    }
    const f = await listedFile(bundle, fileParam);
    const range = parseRange(req.headers.get("range"), f.size);
    // Audited when bytes are actually served (every resumed part too); a 416 transfers nothing.
    if (range !== "unsatisfiable") {
      await auditBundleDownload(access.grant, { version: bundle.version, file: f.name, ip, range: range ? `${range.start}-${range.end}` : null, size: f.size });
    }
    return streamFile(f.path, f.size, range, f.name, contentTypeOf(f.name), bundle.version);
  } catch (err: unknown) {
    return errorResponse(err, "bundle");
  }
}

/** Stream a file (never buffered) with single-range support for resumable downloads (curl -C -). */
function streamFile(path: string, size: number, range: ByteRange | "unsatisfiable" | null, name: string, contentType: string, version?: string): Response {
  const base: Record<string, string> = {
    "Content-Type": contentType,
    "Accept-Ranges": "bytes",
    "Content-Disposition": `attachment; filename="${name}"`,
    ...NO_STORE,
    ...(version ? { "X-PatchGate-Bundle-Version": version } : {}),
  };
  if (range === "unsatisfiable") {
    return new Response(null, { status: 416, headers: { ...base, "Content-Range": `bytes */${size}` } });
  }
  const opts = range ? { start: range.start, end: range.end } : {};
  const length = range ? range.end - range.start + 1 : size;
  const body = length === 0 ? null : (Readable.toWeb(createReadStream(path, opts)) as ReadableStream<Uint8Array>);
  return new Response(body, {
    status: range ? 206 : 200,
    headers: { ...base, "Content-Length": String(length), ...(range ? { "Content-Range": `bytes ${range.start}-${range.end}/${size}` } : {}) },
  });
}
