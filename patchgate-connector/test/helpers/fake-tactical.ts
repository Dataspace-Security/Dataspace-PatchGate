import { createHash } from "node:crypto";
import { createServer as createHttpServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { createServer as createHttpsServer, get as httpsGet } from "node:https";
import { get as httpGet } from "node:http";
import type { AddressInfo } from "node:net";
import type { TacticalAuditLog, TacticalWinUpdate } from "../../src/tactical/types.ts";
import { readBody } from "./common.ts";

/** In-process fake of the Tactical RMM REST endpoints the connector uses. */

export interface FakeAgent {
  agent_id: string;
  hostname: string;
  status: "online" | "offline";
  version: string;
  goarch: string;
  updates: TacticalWinUpdate[];
  software: Array<{ name: string; version: string; publisher?: string }>;
  /** Make every per-agent call fail with this HTTP status. */
  failStatus?: number;
  /** Tactical last_seen (ISO DateTime) / boot_time (epoch seconds, float) as the agent list returns them */
  last_seen?: unknown;
  boot_time?: unknown;
}

export interface RunScriptCall {
  agentId: string;
  script: number;
  env: Record<string, string>;
}

export interface FakeTacticalOptions {
  apiKey: string;
  tls?: { cert: Buffer; key: Buffer };
  /** CA to trust when the fake "PC" downloads from the connector cache. */
  pcCa?: Buffer;
}

let nextPk = 1000;
export function upd(guid: string, over: Partial<TacticalWinUpdate> = {}): TacticalWinUpdate {
  return { id: nextPk++, guid, kb: "KB1", title: `Update ${guid.slice(0, 8)}`, installed: false, action: "nothing", severity: "Important", ...over };
}

export class FakeTactical {
  readonly agents = new Map<string, FakeAgent>();
  readonly calls: Array<{ method: string; path: string; body: unknown }> = [];
  readonly runScripts: RunScriptCall[] = [];
  readonly installs: string[] = [];
  /** Update pks whose approval Tactical's policy keeps forcing back to "approve". */
  readonly policyApproved = new Set<number>();
  /** Override what a script run returns; default: download from PG_REPO_URL/PG_PATH, verify SHA-256. */
  onRunScript?: (call: RunScriptCall) => Promise<string>;
  /** Answer runscript with this HTTP status AFTER recording the call (e.g. a proxy 504 while the script runs). */
  runScriptStatus?: { status: number; body: string };
  /** Tactical's audit log (PATCH /logs/audit/ pages it newest first, like Django's Paginator). */
  readonly auditLogs: TacticalAuditLog[] = [];
  /** Answer PUT /winupdate/<pk>/ with this HTTP status (Tactical refusing a change). */
  putStatus?: number;
  /** GET /agents/ carries has_patches_pending (Tactical 1.5.x); false = an older Tactical without the flag. */
  patchFlag = true;
  private server: Server | undefined;
  url = "";

  constructor(private readonly opts: FakeTacticalOptions) {}

  addAgent(a: Partial<FakeAgent> & { agent_id: string }): FakeAgent {
    const agent: FakeAgent = { hostname: `PC-${a.agent_id.slice(0, 6)}`, status: "online", version: "2.10.0", goarch: "amd64", updates: [], software: [], ...a };
    this.agents.set(agent.agent_id, agent);
    return agent;
  }

  private findUpdate(pk: number): TacticalWinUpdate | undefined {
    for (const a of this.agents.values()) {
      const u = a.updates.find((x) => x.id === pk);
      if (u) return u;
    }
    return undefined;
  }

  async start(): Promise<string> {
    const handler = (req: IncomingMessage, res: ServerResponse) => {
      this.handle(req, res).catch((err: unknown) => {
        res.writeHead(500);
        res.end(String(err));
      });
    };
    const server = this.opts.tls ? createHttpsServer({ cert: this.opts.tls.cert, key: this.opts.tls.key }, handler) : createHttpServer(handler);
    this.server = server;
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
    const port = (server.address() as AddressInfo).port;
    this.url = `${this.opts.tls ? "https" : "http"}://${this.opts.tls ? "localhost" : "127.0.0.1"}:${port}/api`;
    return this.url;
  }

  async stop(): Promise<void> {
    const s = this.server;
    if (!s) return;
    await new Promise<void>((r) => {
      s.close(() => r());
      s.closeAllConnections();
    });
  }

  private json(res: ServerResponse, status: number, body: unknown): void {
    const text = JSON.stringify(body);
    res.writeHead(status, { "content-type": "application/json" });
    res.end(text);
  }

  private async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const raw = await readBody(req);
    const body: unknown = raw.length ? JSON.parse(raw.toString("utf8")) : undefined;
    const path = (req.url ?? "").replace(/^\/api/, "");
    const method = req.method ?? "";
    this.calls.push({ method, path, body });
    if (req.headers["x-api-key"] !== this.opts.apiKey) return this.json(res, 401, { detail: "bad key" });

    let m: RegExpExecArray | null;
    if (method === "GET" && path === "/agents/") {
      return this.json(
        res,
        200,
        [...this.agents.values()].map((a) => ({
          agent_id: a.agent_id,
          hostname: a.hostname,
          status: a.status,
          version: a.version,
          goarch: a.goarch,
          plat: "windows",
          site_name: "HQ",
          client_name: "Bank",
          operating_system: "Windows 11",
          last_seen: a.last_seen,
          boot_time: a.boot_time,
          ...(this.patchFlag ? { has_patches_pending: a.updates.some((u) => u.action === "approve" && !u.installed) } : {}),
        })),
      );
    }
    if ((m = /^\/agents\/([^/]+)\/$/.exec(path)) && method === "GET") {
      const a = this.agents.get(m[1]!);
      if (!a) return this.json(res, 404, "not found");
      if (a.failStatus) return this.json(res, a.failStatus, "Unable to contact the agent");
      return this.json(res, 200, { version: a.version, goarch: a.goarch, hostname: a.hostname });
    }
    if ((m = /^\/winupdate\/([^/]+)\/scan\/$/.exec(path)) && method === "POST") {
      const a = this.agents.get(m[1]!);
      if (!a) return this.json(res, 404, "not found");
      if (a.failStatus) return this.json(res, a.failStatus, "Unable to contact the agent");
      return this.json(res, 200, "ok");
    }
    if ((m = /^\/winupdate\/([^/]+)\/install\/$/.exec(path)) && method === "POST") {
      this.installs.push(m[1]!);
      return this.json(res, 200, "ok");
    }
    if ((m = /^\/winupdate\/(\d+)\/$/.exec(path)) && method === "PUT") {
      if (this.putStatus) return this.json(res, this.putStatus, "refused");
      const u = this.findUpdate(Number(m[1]));
      if (!u) return this.json(res, 404, "not found");
      const action = (body as { action: TacticalWinUpdate["action"] }).action;
      u.action = this.policyApproved.has(u.id) ? "approve" : action;
      return this.json(res, 200, "ok");
    }
    if ((m = /^\/winupdate\/([^/]+)\/$/.exec(path)) && method === "GET") {
      const a = this.agents.get(m[1]!);
      if (!a) return this.json(res, 404, "not found");
      if (a.failStatus) return this.json(res, a.failStatus, "Unable to contact the agent");
      return this.json(res, 200, a.updates);
    }
    if ((m = /^\/software\/([^/]+)\/$/.exec(path))) {
      const a = this.agents.get(m[1]!);
      if (!a) return this.json(res, 404, "not found");
      if (a.failStatus) return this.json(res, a.failStatus, "Unable to contact the agent");
      if (method === "GET") return this.json(res, 200, a.software.length ? { software: a.software } : []);
      return this.json(res, 200, "ok");
    }
    if ((m = /^\/agents\/([^/]+)\/runscript\/$/.exec(path)) && method === "POST") {
      const a = this.agents.get(m[1]!);
      if (!a) return this.json(res, 404, "not found");
      if (a.failStatus) return this.json(res, a.failStatus, "Unable to contact the agent");
      const b = body as { script: number; env_vars: string[] };
      const env = Object.fromEntries(b.env_vars.map((kv) => [kv.slice(0, kv.indexOf("=")), kv.slice(kv.indexOf("=") + 1)]));
      const call = { agentId: a.agent_id, script: b.script, env };
      this.runScripts.push(call);
      if (this.runScriptStatus) return this.json(res, this.runScriptStatus.status, this.runScriptStatus.body);
      const out = await (this.onRunScript ?? ((c) => this.pcInstall(c)))(call);
      return this.json(res, 200, out);
    }
    if (method === "PATCH" && path === "/logs/audit/") {
      const p = (body as { pagination: { sortBy: string; descending: boolean; page: number; rowsPerPage: number } }).pagination;
      const sorted = [...this.auditLogs].sort((a, b) => (p.descending ? b.id - a.id : a.id - b.id));
      const pages = Math.max(1, Math.ceil(sorted.length / p.rowsPerPage));
      const page = Math.min(Math.max(1, p.page), pages); // Paginator.get_page clamps out-of-range pages
      return this.json(res, 200, { audit_logs: sorted.slice((page - 1) * p.rowsPerPage, page * p.rowsPerPage), total: sorted.length });
    }
    return this.json(res, 404, "no route");
  }

  /** What the real install script does first: download PG_REPO_URL/PG_PATH and check the hash. */
  private pcInstall(call: RunScriptCall): Promise<string> {
    const url = `${call.env.PG_REPO_URL}/${call.env.PG_PATH}`;
    return new Promise((resolve) => {
      const done = (r: string) => resolve(`installer log...\nPATCHGATE_RESULT=${r}\n`);
      const getter = url.startsWith("https") ? httpsGet : httpGet;
      const req = getter(url, url.startsWith("https") ? { ca: this.opts.pcCa } : {}, (res) => {
        if (res.statusCode !== 200) {
          res.resume();
          done(`FAIL:download HTTP ${res.statusCode}`);
          return;
        }
        const h = createHash("sha256");
        res.on("data", (c: Buffer) => h.update(c));
        res.on("end", () => done(h.digest("hex") === call.env.PG_SHA256 ? "OK" : "FAIL:hash mismatch"));
      });
      req.on("error", (e) => done(`FAIL:${e.message}`));
    });
  }
}
