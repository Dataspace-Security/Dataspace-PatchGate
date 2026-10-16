import { z } from "zod";
import {
  agentDetailSchema,
  agentSchema,
  agentSoftwareSchema,
  winUpdateSchema,
  type SoftwareItem,
  type TacticalAgent,
  type TacticalAgentDetail,
  type TacticalWinUpdate,
  type WinUpdateAction,
} from "./types";

/**
 * Thin client for the (offline, internal) Tactical RMM REST API.
 * Tactical is a delivery pipe only — all decisions are made in PatchGate.
 */

export class TacticalError extends Error {
  constructor(
    message: string,
    readonly status?: number,
  ) {
    super(message);
    this.name = "TacticalError";
  }
}

export interface TacticalClientOptions {
  baseUrl: string;
  apiKey: string;
  timeoutMs: number;
  fetchImpl?: typeof fetch;
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
}

const AGENT_ID = /^[A-Za-z0-9_-]{8,64}$/;

function assertAgentId(id: string): string {
  if (!AGENT_ID.test(id)) throw new TacticalError(`Invalid agent id`);
  return id;
}

export function createTacticalClient(opts: TacticalClientOptions): TacticalClient {
  const doFetch = opts.fetchImpl ?? fetch;
  const base = opts.baseUrl.replace(/\/+$/, "");

  async function call<T>(method: string, path: string, schema: z.ZodType<T>, body?: unknown, timeoutMs = opts.timeoutMs) {
    let res: Response;
    try {
      res = await doFetch(`${base}${path}`, {
        method,
        headers: { "X-API-KEY": opts.apiKey, "Content-Type": "application/json" },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: AbortSignal.timeout(timeoutMs),
        cache: "no-store",
        redirect: "error", // never forward X-API-KEY to a redirect target
      });
    } catch (err: unknown) {
      const reason = err instanceof Error ? err.message : "unknown error";
      throw new TacticalError(`Tactical unreachable (${method} ${path}): ${reason}`);
    }
    if (!res.ok) throw new TacticalError(`Tactical ${method} ${path} -> ${res.status}`, res.status);

    const json: unknown = await res.json().catch(() => null);
    const parsed = schema.safeParse(json);
    if (!parsed.success) throw new TacticalError(`Unexpected Tactical response for ${path}`);
    return parsed.data;
  }

  const anyResponse = z.unknown();

  return {
    listAgents: () => call("GET", "/agents/", z.array(agentSchema)),

    getAgent: async (agentId) => call("GET", `/agents/${assertAgentId(agentId)}/`, agentDetailSchema),

    scanUpdates: async (agentId) => {
      await call("POST", `/winupdate/${assertAgentId(agentId)}/scan/`, anyResponse);
    },

    getUpdates: async (agentId) =>
      call("GET", `/winupdate/${assertAgentId(agentId)}/`, z.array(winUpdateSchema)),

    setUpdateAction: async (updatePk, action) => {
      await call("PUT", `/winupdate/${Math.trunc(updatePk)}/`, anyResponse, { action });
    },

    installApproved: async (agentId) => {
      await call("POST", `/winupdate/${assertAgentId(agentId)}/install/`, anyResponse);
    },

    getSoftware: async (agentId) =>
      call("GET", `/software/${assertAgentId(agentId)}/`, agentSoftwareSchema),

    refreshSoftware: async (agentId) => {
      await call("PUT", `/software/${assertAgentId(agentId)}/`, anyResponse);
    },

    runScript: async (agentId, input) => {
      const out = await call("POST", `/agents/${assertAgentId(agentId)}/runscript/`, anyResponse, {
        script: input.scriptId,
        args: [],
        output: "wait",
        timeout: input.timeoutSec,
        run_as_user: false,
        env_vars: Object.entries(input.envVars).map(([k, v]) => `${k}=${v}`),
      },
      // Tactical holds the request open until the script finishes: wait script timeout + margin.
      (input.timeoutSec + 30) * 1000);
      return typeof out === "string" ? out : JSON.stringify(out);
    },
  };
}
