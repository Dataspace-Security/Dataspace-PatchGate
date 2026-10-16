/**
 * Fake Tactical RMM REST API for the connector end-to-end run (e2e-connector/run-e2e.ts).
 * Implements exactly the calls the PatchGate Connector makes. The install script (runscript) behaves
 * like the real Install-PatchGatePackage.ps1 step one: it downloads PG_REPO_URL/PG_PATH from the
 * connector's site cache and checks the SHA-256; on success the "PC" reports the app as installed.
 */
import { createHash } from "node:crypto";
import { createServer, get as httpGet, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";

export interface FakeUpdate {
  id: number;
  guid: string;
  kb: string | null;
  title: string | null;
  installed: boolean;
  action: "inherit" | "approve" | "ignore" | "nothing";
  severity: string | null;
}

export interface FakeAgent {
  agent_id: string;
  hostname: string;
  version: string;
  goarch: string;
  updates: FakeUpdate[];
  software: { name: string; version: string; publisher?: string }[];
}

export interface ScriptRun {
  agentId: string;
  script: number;
  env: Record<string, string>;
  result: string;
}

async function readBody(req: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  return Buffer.concat(chunks);
}

function download(url: string): Promise<{ status: number; sha256: string; bytes: number }> {
  return new Promise((resolve, reject) => {
    httpGet(url, (res) => {
      const h = createHash("sha256");
      let bytes = 0;
      res.on("data", (c: Buffer) => {
        bytes += c.length;
        h.update(c);
      });
      res.on("end", () => resolve({ status: res.statusCode ?? 0, sha256: h.digest("hex"), bytes }));
      res.on("error", reject);
    }).on("error", reject);
  });
}

export class FakeTactical {
  readonly agents = new Map<string, FakeAgent>();
  readonly scriptRuns: ScriptRun[] = [];
  readonly calls: string[] = [];
  /** name/version the "installer" adds to the PC inventory, keyed by PG_APP_ID */
  readonly installs = new Map<string, { name: string; version: string; publisher: string }>();
  private server: Server | undefined;
  url = "";

  constructor(private readonly apiKey: string) {}

  addAgent(a: Partial<FakeAgent> & { agent_id: string; hostname: string }): FakeAgent {
    const agent: FakeAgent = { version: "2.10.0", goarch: "amd64", updates: [], software: [], ...a };
    this.agents.set(agent.agent_id, agent);
    return agent;
  }

  async start(): Promise<string> {
    const server = createServer((req, res) => {
      this.handle(req, res).catch((err: unknown) => {
        res.writeHead(500);
        res.end(String(err));
      });
    });
    this.server = server;
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
    this.url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/api`;
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
    res.writeHead(status, { "content-type": "application/json" });
    res.end(JSON.stringify(body));
  }

  private async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const raw = await readBody(req);
    const body: unknown = raw.length ? JSON.parse(raw.toString("utf8")) : undefined;
    const path = (req.url ?? "").replace(/^\/api/, "");
    const method = req.method ?? "";
    this.calls.push(`${method} ${path}`);
    if (req.headers["x-api-key"] !== this.apiKey) return this.json(res, 401, { detail: "bad key" });

    let m: RegExpExecArray | null;
    if (method === "GET" && path === "/agents/") {
      return this.json(
        res,
        200,
        [...this.agents.values()].map((a) => ({
          agent_id: a.agent_id, hostname: a.hostname, status: "online", version: a.version, goarch: a.goarch,
          plat: "windows", site_name: "HQ", client_name: "Bank A", operating_system: "Windows 11 Enterprise",
        })),
      );
    }
    if ((m = /^\/agents\/([^/]+)\/$/.exec(path)) && method === "GET") {
      const a = this.agents.get(m[1]);
      return a ? this.json(res, 200, { version: a.version, goarch: a.goarch, hostname: a.hostname }) : this.json(res, 404, "not found");
    }
    if ((m = /^\/winupdate\/([^/]+)\/scan\/$/.exec(path)) && method === "POST") {
      return this.agents.has(m[1]) ? this.json(res, 200, "ok") : this.json(res, 404, "not found");
    }
    if ((m = /^\/winupdate\/([^/]+)\/$/.exec(path)) && method === "GET") {
      const a = this.agents.get(m[1]);
      return a ? this.json(res, 200, a.updates) : this.json(res, 404, "not found");
    }
    if ((m = /^\/software\/([^/]+)\/$/.exec(path))) {
      const a = this.agents.get(m[1]);
      if (!a) return this.json(res, 404, "not found");
      if (method === "GET") return this.json(res, 200, a.software.length ? { software: a.software } : []);
      return this.json(res, 200, "ok"); // PUT = refresh inventory
    }
    if ((m = /^\/agents\/([^/]+)\/runscript\/$/.exec(path)) && method === "POST") {
      const a = this.agents.get(m[1]);
      if (!a) return this.json(res, 404, "not found");
      const b = body as { script: number; env_vars: string[] };
      const env = Object.fromEntries(b.env_vars.map((kv) => [kv.slice(0, kv.indexOf("=")), kv.slice(kv.indexOf("=") + 1)]));
      const result = await this.install(a, env);
      this.scriptRuns.push({ agentId: a.agent_id, script: b.script, env, result });
      return this.json(res, 200, `installer log...\nPATCHGATE_RESULT=${result}\n`);
    }
    return this.json(res, 404, "no route");
  }

  /** The PC downloads from the SITE CACHE (never from PatchGate / the internet) and verifies the hash. */
  private async install(a: FakeAgent, env: Record<string, string>): Promise<string> {
    try {
      const got = await download(`${env.PG_REPO_URL}/${env.PG_PATH}`);
      if (got.status !== 200) return `FAIL:download HTTP ${got.status}`;
      if (got.sha256 !== env.PG_SHA256) return "FAIL:hash mismatch";
    } catch (err: unknown) {
      return `FAIL:${err instanceof Error ? err.message : "download error"}`;
    }
    const sw = this.installs.get(env.PG_APP_ID);
    if (sw) a.software = [...a.software.filter((s) => s.name !== sw.name), sw];
    return "OK";
  }
}
