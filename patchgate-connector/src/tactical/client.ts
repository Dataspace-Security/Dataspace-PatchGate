import type { Agent as HttpAgent } from "node:http";
import type { Agent as HttpsAgent } from "node:https";
import { z } from "zod";
import { createAgent, httpRequest, HttpNetworkError } from "../util/http.ts";
import {
  agentDetailSchema,
  agentSchema,
  agentSoftwareSchema,
  auditLogPageSchema,
  winUpdateSchema,
  type TacticalAuditLogPage,
  type SoftwareItem,
  type TacticalAgent,
  type TacticalAgentDetail,
  type TacticalWinUpdate,
  type WinUpdateAction,
} from "./types.ts";

/**
 * Thin client for the local (offline) Tactical RMM REST API. Only the typed operations the job
 * executors need are exposed — there is deliberately no generic "call any endpoint" method.
 * Adapted from patchgate-web/src/lib/tactical/client.ts (node:https so the bank CA can be pinned).
 */

export class TacticalError extends Error {
  constructor(
    message: string,
    /** HTTP status; undefined = transport failure / timeout (request may or may not have run). */
    readonly status?: number,
    /** Short, sanitised response text (Tactical error messages; never contains our key). */
    readonly detail?: string,
  ) {
    super(message);
    this.name = "TacticalError";
  }
}

export interface RunScriptInput {
  scriptId: number;
  /** Passed as env vars (KEY=VALUE), NOT args: Tactical joins args into a command line. */
  envVars: Record<string, string>;
  timeoutSec: number;
}

export interface TacticalClient {
  listAgents(): Promise<TacticalAgent[]>;
  getAgent(agentId: string): Promise<TacticalAgentDetail>;
  scanUpdates(agentId: string): Promise<void>;
  getUpdates(agentId: string): Promise<TacticalWinUpdate[]>;
  setUpdateAction(updatePk: number, action: WinUpdateAction): Promise<void>;
  installApproved(agentId: string): Promise<void>;
  getSoftware(agentId: string): Promise<SoftwareItem[]>;
  refreshSoftware(agentId: string): Promise<void>;
  runScript(agentId: string, input: RunScriptInput): Promise<string>;
  /** One page of Tactical's audit log, newest first (read-only; needs can_view_auditlogs). */
  auditLogPage(page: number, rowsPerPage: number): Promise<TacticalAuditLogPage>;
}

export interface TacticalClientOptions {
  baseUrl: string;
  apiKey: string;
  timeoutMs: number;
  ca?: string | Buffer;
}

const AGENT_ID = /^[A-Za-z0-9_-]{6,64}$/;

function assertAgentId(id: string): string {
  if (!AGENT_ID.test(id)) throw new TacticalError("invalid agent id", 400);
  return id;
}

function sanitize(text: string): string {
  return text.replace(/[^\x20-\x7e]/g, " ").slice(0, 300);
}

export function createTacticalClient(opts: TacticalClientOptions): TacticalClient {
  const base = new URL(opts.baseUrl.replace(/\/+$/, "") + "/");
  const agent: HttpAgent | HttpsAgent = createAgent(base, { ca: opts.ca, maxSockets: 16 });

  async function call<T>(method: string, path: string, schema: z.ZodType<T>, body?: unknown, timeoutMs = opts.timeoutMs): Promise<T> {
    const url = new URL(path.replace(/^\//, ""), base);
    let res;
    try {
      res = await httpRequest({
        method,
        url,
        agent,
        timeoutMs,
        headers: { "x-api-key": opts.apiKey, "content-type": "application/json", accept: "application/json" },
        body: body === undefined ? undefined : JSON.stringify(body),
        maxResponseBytes: 64 * 1024 * 1024,
      });
    } catch (err) {
      const reason = err instanceof HttpNetworkError ? err.message : "unknown error";
      throw new TacticalError(`Tactical unreachable (${method} ${path}): ${reason}`);
    }
    const text = res.body.toString("utf8");
    if (res.status < 200 || res.status >= 300) {
      throw new TacticalError(`Tactical ${method} ${path} -> ${res.status}`, res.status, sanitize(text));
    }
    let json: unknown = null;
    try {
      json = text.length ? JSON.parse(text) : null;
    } catch {
      json = text; // some Tactical endpoints answer with a bare string
    }
    const parsed = schema.safeParse(json);
    if (!parsed.success) throw new TacticalError(`unexpected Tactical response for ${method} ${path}`, res.status);
    return parsed.data;
  }

  const anyResponse = z.unknown();

  return {
    listAgents: () => call("GET", "/agents/", z.array(agentSchema), undefined, Math.max(opts.timeoutMs, 120_000)),
    getAgent: async (agentId) => call("GET", `/agents/${assertAgentId(agentId)}/`, agentDetailSchema),
    scanUpdates: async (agentId) => {
      await call("POST", `/winupdate/${assertAgentId(agentId)}/scan/`, anyResponse);
    },
    getUpdates: async (agentId) => call("GET", `/winupdate/${assertAgentId(agentId)}/`, z.array(winUpdateSchema)),
    setUpdateAction: async (updatePk, action) => {
      if (!Number.isSafeInteger(updatePk) || updatePk < 0) throw new TacticalError("invalid update id", 400);
      await call("PUT", `/winupdate/${updatePk}/`, anyResponse, { action });
    },
    installApproved: async (agentId) => {
      await call("POST", `/winupdate/${assertAgentId(agentId)}/install/`, anyResponse);
    },
    getSoftware: async (agentId) => call("GET", `/software/${assertAgentId(agentId)}/`, agentSoftwareSchema),
    refreshSoftware: async (agentId) => {
      await call("PUT", `/software/${assertAgentId(agentId)}/`, anyResponse);
    },
    runScript: async (agentId, input) => {
      const out = await call(
        "POST",
        `/agents/${assertAgentId(agentId)}/runscript/`,
        anyResponse,
        {
          script: input.scriptId,
          args: [],
          output: "wait",
          timeout: input.timeoutSec,
          run_as_user: false,
          env_vars: Object.entries(input.envVars).map(([k, v]) => `${k}=${v}`),
        },
        // Tactical holds the request open until the script finishes: wait script timeout + margin.
        (input.timeoutSec + 30) * 1000,
      );
      return typeof out === "string" ? out : JSON.stringify(out);
    },
    auditLogPage: async (page, rowsPerPage) => {
      if (!Number.isSafeInteger(page) || page < 1 || !Number.isSafeInteger(rowsPerPage) || rowsPerPage < 1 || rowsPerPage > 1000) {
        throw new TacticalError("invalid audit log page", 400);
      }
      // Tactical's audit view is a PATCH with a pagination body (logs/views.py GetAuditLogs); newest first.
      return call("PATCH", "/logs/audit/", auditLogPageSchema, { pagination: { sortBy: "id", descending: true, page, rowsPerPage } });
    },
  };
}

/** Transient Tactical failures that PatchGate may safely re-queue (NOT for script runs: see below). */
export function isRetryableTactical(err: unknown): boolean {
  if (!(err instanceof TacticalError)) return false;
  if (err.status === undefined) return true; // unreachable / timeout
  if (err.status >= 500 || err.status === 429 || err.status === 408) return true;
  // Tactical answers 400 "Unable to contact the agent" when the PC is offline.
  return err.status === 400 && /unable to contact|offline|timed? ?out/i.test(err.detail ?? "");
}

/** Gateway / proxy statuses that a reverse proxy in front of Tactical returns while the upstream still works. */
const GATEWAY_STATUSES = new Set([408, 502, 503, 504]);

/**
 * runScript failures after which the script MAY be running (or have run) on the PC: no HTTP answer
 * (connection lost / client timeout), a proxy gateway error or timeout (408/502/503/504: nginx gives up
 * while Tactical keeps waiting for the agent), or Tactical's own "timed out" answer. Re-running would
 * start a second installer, so these are reported as outcome unknown, never retried.
 */
export function isRunScriptOutcomeUnknown(err: unknown): boolean {
  if (!(err instanceof TacticalError)) return false;
  if (err.status === undefined) return true;
  if (GATEWAY_STATUSES.has(err.status)) return true;
  return err.status === 400 && /timed? ?out/i.test(err.detail ?? "") && !/unable to contact|offline/i.test(err.detail ?? "");
}
