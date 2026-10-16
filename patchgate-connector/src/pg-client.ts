import { randomBytes, sign, type KeyObject } from "node:crypto";
import type { IncomingMessage } from "node:http";
import { z } from "zod";
import {
  API_PREFIX,
  auditRelayResponseSchema,
  enrollProofMessage,
  enrollRequestSchema,
  enrollResponseSchema,
  HEADERS,
  heartbeatResponseSchema,
  heartbeatSchema,
  jobResultSchema,
  MAX_JOBS_PER_POLL,
  rawFromPublicKey,
  signRequest,
  tacticalPushResponseSchema,
  tacticalPushSchema,
  type Heartbeat,
  type JobResult,
  type TacticalPush,
} from "./protocol.ts";
import { createAgent, headerValue, httpRequest, httpRequestStream, HttpNetworkError, type HttpResponse } from "./util/http.ts";

/**
 * Outbound-only client for the PatchGate connector API (/api/connector/v1).
 * Every call except enrol carries an Ed25519 request signature (protocol.ts §1).
 */

export class PatchGateError extends Error {
  constructor(
    message: string,
    readonly status: number | undefined,
    readonly retryable: boolean,
    readonly retryAfterMs?: number,
  ) {
    super(message);
    this.name = "PatchGateError";
  }
}

export type HeartbeatResponse = z.infer<typeof heartbeatResponseSchema>;
export type AuditRelayResponse = z.infer<typeof auditRelayResponseSchema>;
export type EnrollResponse = z.infer<typeof enrollResponseSchema>;
export type TacticalPushResponse = z.infer<typeof tacticalPushResponseSchema>;
export type PostResultOutcome = "accepted" | "duplicate" | "unknown-job" | "rejected";

const jobsResponseSchema = z.object({ jobs: z.array(z.unknown()).max(MAX_JOBS_PER_POLL) });
const JOB_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
export const SHA256_RE = /^[a-f0-9]{64}$/;
const SEQ_RE = /^\d{1,24}$/;

export interface PatchGateClientOptions {
  serverUrl: string;
  ca?: string | Buffer;
  connectorId: string;
  privateKey: KeyObject;
  timeoutMs: number;
}

export interface PatchGateClient {
  getJobs(waitSec: number, signal?: AbortSignal): Promise<unknown[]>;
  postResult(jobId: string, result: JobResult, signal?: AbortSignal): Promise<PostResultOutcome>;
  heartbeat(hb: Heartbeat, signal?: AbortSignal): Promise<HeartbeatResponse>;
  getAudit(afterSeq: string, limit: number, signal?: AbortSignal): Promise<AuditRelayResponse>;
  /** Real-time Tactical guard (protocol §8): out-of-band audit entries + approvals reset. */
  pushTacticalEvents(push: TacticalPush, signal?: AbortSignal): Promise<TacticalPushResponse>;
  downloadPackage(sha256: string, signal?: AbortSignal): Promise<{ res: IncomingMessage; abort: (err: Error) => void }>;
}

function parseRetryAfter(v: string | undefined): number | undefined {
  if (!v) return undefined;
  const s = Number(v);
  if (Number.isFinite(s) && s >= 0) return Math.min(s, 3600) * 1000;
  const d = Date.parse(v);
  return Number.isFinite(d) ? Math.max(0, Math.min(d - Date.now(), 3_600_000)) : undefined;
}

function statusError(what: string, res: { status: number; headers: HttpResponse["headers"] }): PatchGateError {
  const s = res.status;
  const retryable = s === 408 || s === 425 || s === 429 || s >= 500;
  const hint = s === 401 || s === 403 ? " (request authentication rejected: revoked connector, clock skew or wrong key?)" : "";
  return new PatchGateError(`PatchGate ${what} -> HTTP ${s}${hint}`, s, retryable, parseRetryAfter(headerValue(res.headers, "retry-after")));
}

function parseJson<T>(what: string, res: HttpResponse, schema: z.ZodType<T>): T {
  let json: unknown;
  try {
    json = JSON.parse(res.body.toString("utf8"));
  } catch {
    throw new PatchGateError(`PatchGate ${what}: response is not JSON`, res.status, true);
  }
  const parsed = schema.safeParse(json);
  if (!parsed.success) throw new PatchGateError(`PatchGate ${what}: unexpected response shape`, res.status, false);
  return parsed.data;
}

function baseUrl(serverUrl: string): URL {
  const u = new URL(serverUrl);
  if (u.username || u.password) throw new Error("server URL must not contain credentials");
  return new URL(u.origin);
}

/** POST /enroll with proof of possession. Not signed (the connector has no identity yet). */
export async function enroll(opts: {
  serverUrl: string;
  ca?: string | Buffer;
  code: string;
  publicKey: KeyObject;
  privateKey: KeyObject;
  version: string;
  timeoutMs: number;
}): Promise<EnrollResponse> {
  const publicKey = rawFromPublicKey(opts.publicKey);
  const proof = sign(null, Buffer.from(enrollProofMessage(opts.code, publicKey)), opts.privateKey).toString("base64");
  const body = enrollRequestSchema.parse({ code: opts.code, publicKey, version: opts.version, proof });
  const url = new URL(`${API_PREFIX}/enroll`, baseUrl(opts.serverUrl));
  const agent = createAgent(url, { ca: opts.ca, keepAlive: false });
  let res: HttpResponse;
  try {
    res = await httpRequest({
      method: "POST",
      url,
      agent,
      timeoutMs: opts.timeoutMs,
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify(body),
      maxResponseBytes: 64 * 1024,
    });
  } catch (err) {
    throw new PatchGateError(`enrolment failed: ${err instanceof Error ? err.message : "network error"}`, undefined, true);
  }
  if (res.status !== 200 && res.status !== 201) throw statusError("enroll", res);
  return parseJson("enroll", res, enrollResponseSchema);
}

export function createPatchGateClient(opts: PatchGateClientOptions): PatchGateClient {
  const base = baseUrl(opts.serverUrl);
  const agent = createAgent(base, { ca: opts.ca, maxSockets: 16 });

  function signedHeaders(method: string, pathWithQuery: string, body: string): Record<string, string> {
    const timestamp = String(Date.now());
    const nonce = randomBytes(16).toString("base64url");
    return {
      [HEADERS.connector]: opts.connectorId,
      [HEADERS.timestamp]: timestamp,
      [HEADERS.nonce]: nonce,
      [HEADERS.signature]: signRequest(opts.privateKey, method, pathWithQuery, timestamp, nonce, body),
    };
  }

  async function call(method: "GET" | "POST", pathWithQuery: string, body: string, timeoutMs: number, signal?: AbortSignal): Promise<HttpResponse> {
    const url = new URL(pathWithQuery, base);
    const headers: Record<string, string> = { accept: "application/json", ...signedHeaders(method, pathWithQuery, body) };
    if (method === "POST") headers["content-type"] = "application/json";
    try {
      return await httpRequest({ method, url, agent, timeoutMs, headers, body: method === "POST" ? body : undefined, signal, maxResponseBytes: 32 * 1024 * 1024 });
    } catch (err) {
      const msg = err instanceof HttpNetworkError ? err.message : "network error";
      throw new PatchGateError(`PatchGate ${method} ${pathWithQuery.split("?")[0]}: ${msg}`, undefined, true);
    }
  }

  return {
    async getJobs(waitSec, signal) {
      const wait = Math.max(0, Math.min(25, Math.trunc(waitSec)));
      const res = await call("GET", `${API_PREFIX}/jobs?wait=${wait}`, "", opts.timeoutMs + wait * 1000, signal);
      if (res.status === 204) return [];
      if (res.status !== 200) throw statusError("GET jobs", res);
      return parseJson("GET jobs", res, jobsResponseSchema).jobs;
    },

    async postResult(jobId, result, signal) {
      if (!JOB_ID_RE.test(jobId)) throw new PatchGateError("invalid job id", undefined, false);
      const body = JSON.stringify(jobResultSchema.parse(result));
      const res = await call("POST", `${API_PREFIX}/jobs/${jobId}/result`, body, opts.timeoutMs, signal);
      if (res.status >= 200 && res.status < 300) return "accepted";
      if (res.status === 409) return "duplicate"; // first accepted result wins
      if (res.status === 404 || res.status === 410) return "unknown-job";
      if (res.status === 400 || res.status === 422) return "rejected";
      throw statusError("POST result", res);
    },

    async heartbeat(hb, signal) {
      const body = JSON.stringify(heartbeatSchema.parse(hb));
      const res = await call("POST", `${API_PREFIX}/heartbeat`, body, opts.timeoutMs, signal);
      if (res.status !== 200) throw statusError("POST heartbeat", res);
      return parseJson("heartbeat", res, heartbeatResponseSchema);
    },

    async getAudit(afterSeq, limit, signal) {
      if (!SEQ_RE.test(afterSeq)) throw new PatchGateError("invalid audit seq", undefined, false);
      const lim = Math.max(1, Math.min(500, Math.trunc(limit)));
      const res = await call("GET", `${API_PREFIX}/audit?after=${afterSeq}&limit=${lim}`, "", opts.timeoutMs, signal);
      if (res.status !== 200) throw statusError("GET audit", res);
      return parseJson("audit", res, auditRelayResponseSchema);
    },

    async pushTacticalEvents(push, signal) {
      const body = JSON.stringify(tacticalPushSchema.parse(push));
      const res = await call("POST", `${API_PREFIX}/tactical-events`, body, opts.timeoutMs, signal);
      if (res.status !== 200) throw statusError("POST tactical-events", res);
      return parseJson("tactical-events", res, tacticalPushResponseSchema);
    },

    async downloadPackage(sha256, signal) {
      if (!SHA256_RE.test(sha256)) throw new PatchGateError("invalid sha256", undefined, false);
      const path = `${API_PREFIX}/packages/${sha256}`;
      const url = new URL(path, base);
      let out;
      try {
        out = await httpRequestStream({
          method: "GET",
          url,
          agent,
          timeoutMs: opts.timeoutMs,
          signal,
          headers: { accept: "application/octet-stream", ...signedHeaders("GET", path, "") },
        });
      } catch (err) {
        const msg = err instanceof HttpNetworkError ? err.message : "network error";
        throw new PatchGateError(`PatchGate GET package: ${msg}`, undefined, true);
      }
      if (out.res.statusCode !== 200) {
        out.res.resume();
        throw statusError("GET package", { status: out.res.statusCode ?? 0, headers: out.res.headers });
      }
      return out;
    },
  };
}
