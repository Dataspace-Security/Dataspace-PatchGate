import { createHash, generateKeyPairSync, randomBytes, verify } from "node:crypto";
import { createServer as createHttpServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import type { AddressInfo } from "node:net";
import {
  API_PREFIX,
  enrollProofMessage,
  enrollRequestSchema,
  HEADERS,
  heartbeatSchema,
  jobResultSchema,
  NONCE_RE,
  publicKeyFromRaw,
  rawFromPublicKey,
  signJob,
  timestampFresh,
  verifyRequest,
  type Heartbeat,
  type JobEnvelope,
  type JobResult,
  type JobType,
  type SignedJob,
} from "../../src/protocol.ts";
import { readBody } from "./common.ts";

/**
 * In-process FAKE PatchGate implementing the connector protocol (server side), used to test the
 * connector end-to-end: enrolment with proof of possession, signed requests (timestamp + nonce +
 * signature), signed job queue with long poll, results (first wins), packages, audit relay, heartbeat.
 */

export interface AuditRecord {
  seq: string;
  ts: string;
  actor: string;
  action: string;
  entity: string;
  entityId: string;
  hash: string;
  prevHash?: string | null;
  payload: unknown;
}

export class FakePatchGate {
  readonly jobKey = generateKeyPairSync("ed25519");
  readonly jobSigningPublicKey = rawFromPublicKey(this.jobKey.publicKey);
  readonly codes = new Map<string, { tenantId: string; used: boolean }>();
  readonly connectors = new Map<string, { publicKey: string; tenantId: string }>();
  readonly nonces = new Set<string>();
  readonly queue: SignedJob[] = [];
  readonly knownJobs = new Set<string>();
  readonly results = new Map<string, JobResult>();
  readonly resultPosts: Array<{ jobId: string; result: JobResult; status: number }> = [];
  readonly heartbeats: Heartbeat[] = [];
  readonly packages = new Map<string, Buffer>();
  readonly audit: AuditRecord[] = [];
  /** seqs a (compromised) server silently leaves out of /audit pages. */
  readonly auditWithheld = new Set<string>();
  readonly authFailures: string[] = [];
  readonly packageDownloads: string[] = [];
  heartbeatResponse = { maxConcurrentInstalls: 3, bandwidthLimitMbps: null as number | null };
  /** Force the next N result posts to fail with 503 (tests retry). */
  failResultPosts = 0;
  /** Answer the next result posts with these HTTP statuses (consumed in order; e.g. 413, 403). */
  readonly resultStatusQueue: number[] = [];
  /** Every result post attempt that reached the route (incl. forced failures). */
  resultAttempts = 0;
  private waiters: Array<() => void> = [];
  private server: Server | undefined;
  url = "";

  constructor(private readonly tls?: { cert: Buffer; key: Buffer }) {}

  addEnrollCode(tenantId = "tenant-bank-a"): string {
    const code = Array.from({ length: 5 }, () => randomBytes(4).toString("hex").slice(0, 4).toUpperCase().replace(/[^A-Z0-9]/g, "A")).join("-");
    this.codes.set(code, { tenantId, used: false });
    return code;
  }

  /** Build + sign a job for a connector (does not queue it). */
  makeJob<T extends JobType>(connectorId: string, type: T, payload: unknown, over: Partial<JobEnvelope> = {}): SignedJob {
    const now = Date.now();
    const env: JobEnvelope = {
      v: 1,
      id: `job_${randomBytes(6).toString("hex")}`,
      tenantId: this.connectors.get(connectorId)?.tenantId ?? "tenant-bank-a",
      connectorId,
      type,
      payload,
      notBefore: new Date(now - 60_000).toISOString(),
      expiresAt: new Date(now + 3_600_000).toISOString(),
      ...over,
    };
    return signJob(this.jobKey.privateKey, env);
  }

  enqueue(job: SignedJob): void {
    this.knownJobs.add(job.id);
    this.queue.push(job);
    const w = this.waiters;
    this.waiters = [];
    for (const f of w) f();
  }

  addPackage(bytes: Buffer): string {
    const sha = createHash("sha256").update(bytes).digest("hex");
    this.packages.set(sha, bytes);
    return sha;
  }

  async start(): Promise<string> {
    const handler = (req: IncomingMessage, res: ServerResponse) => {
      this.handle(req, res).catch((err: unknown) => {
        if (!res.headersSent) res.writeHead(500);
        res.end(String(err));
      });
    };
    const server = this.tls ? createHttpsServer({ cert: this.tls.cert, key: this.tls.key }, handler) : createHttpServer(handler);
    this.server = server;
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
    const port = (server.address() as AddressInfo).port;
    this.url = `${this.tls ? "https://localhost" : "http://127.0.0.1"}:${port}`;
    return this.url;
  }

  async stop(): Promise<void> {
    for (const w of this.waiters) w();
    this.waiters = [];
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

  /** Protocol §1: verify the connector's request signature, timestamp and nonce. */
  private authenticate(req: IncomingMessage, body: Buffer): string | null {
    const h = (n: string) => {
      const v = req.headers[n];
      return typeof v === "string" ? v : "";
    };
    const id = h(HEADERS.connector);
    const ts = h(HEADERS.timestamp);
    const nonce = h(HEADERS.nonce);
    const sig = h(HEADERS.signature);
    const c = this.connectors.get(id);
    const fail = (why: string) => {
      this.authFailures.push(why);
      return null;
    };
    if (!c) return fail("unknown connector");
    if (!timestampFresh(ts, Date.now())) return fail("stale timestamp");
    if (!NONCE_RE.test(nonce)) return fail("bad nonce");
    if (this.nonces.has(nonce)) return fail("replayed nonce");
    if (!verifyRequest(c.publicKey, sig, req.method ?? "", req.url ?? "", ts, nonce, body)) return fail("bad signature");
    this.nonces.add(nonce);
    return id;
  }

  private async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await readBody(req);
    const url = new URL(req.url ?? "/", "http://x");
    const path = url.pathname;
    if (!path.startsWith(API_PREFIX)) return this.json(res, 404, { error: "not found" });
    const route = path.slice(API_PREFIX.length);

    if (route === "/enroll" && req.method === "POST") {
      const parsed = enrollRequestSchema.safeParse(JSON.parse(body.toString("utf8")));
      if (!parsed.success) return this.json(res, 400, { error: "invalid" });
      const { code, publicKey, proof } = parsed.data;
      const entry = this.codes.get(code);
      if (!entry || entry.used) return this.json(res, 403, { error: "invalid code" });
      if (!verify(null, Buffer.from(enrollProofMessage(code, publicKey)), publicKeyFromRaw(publicKey), Buffer.from(proof, "base64"))) {
        return this.json(res, 403, { error: "bad proof" });
      }
      entry.used = true;
      const connectorId = `conn_${randomBytes(6).toString("hex")}`;
      this.connectors.set(connectorId, { publicKey, tenantId: entry.tenantId });
      return this.json(res, 201, { connectorId, tenantId: entry.tenantId, name: "Bank A HQ", jobSigningPublicKey: this.jobSigningPublicKey });
    }

    const connectorId = this.authenticate(req, body);
    if (!connectorId) return this.json(res, 401, { error: "unauthorized" });

    if (route === "/jobs" && req.method === "GET") {
      const wait = Math.min(25, Number(url.searchParams.get("wait") ?? "0"));
      const take = () => {
        const mine = this.queue.filter((j) => j.connectorId === connectorId || !this.connectors.has(j.connectorId)).slice(0, 20);
        for (const j of mine) this.queue.splice(this.queue.indexOf(j), 1);
        return mine;
      };
      let jobs = take();
      if (jobs.length === 0 && wait > 0) {
        await new Promise<void>((r) => {
          const t = setTimeout(r, wait * 1000);
          this.waiters.push(() => {
            clearTimeout(t);
            r();
          });
        });
        jobs = take();
      }
      return this.json(res, 200, { jobs });
    }

    const resultMatch = /^\/jobs\/([A-Za-z0-9_-]+)\/result$/.exec(route);
    if (resultMatch && req.method === "POST") {
      const jobId = resultMatch[1]!;
      this.resultAttempts++;
      const forced = this.resultStatusQueue.shift();
      if (forced !== undefined) {
        const parsedForced = jobResultSchema.safeParse(JSON.parse(body.toString("utf8")));
        if (parsedForced.success) this.resultPosts.push({ jobId, result: parsedForced.data, status: forced });
        return this.json(res, forced, { error: "forced" });
      }
      if (this.failResultPosts > 0) {
        this.failResultPosts--;
        res.writeHead(503, { "retry-after": "0" });
        res.end();
        return;
      }
      const parsed = jobResultSchema.safeParse(JSON.parse(body.toString("utf8")));
      if (!parsed.success) return this.json(res, 400, { error: "invalid result" });
      if (!this.knownJobs.has(jobId)) {
        this.resultPosts.push({ jobId, result: parsed.data, status: 404 });
        return this.json(res, 404, { error: "unknown job" });
      }
      const status = this.results.has(jobId) ? 409 : 200;
      if (status === 200) this.results.set(jobId, parsed.data);
      this.resultPosts.push({ jobId, result: parsed.data, status });
      return this.json(res, status, { ok: status === 200 });
    }

    if (route === "/heartbeat" && req.method === "POST") {
      const parsed = heartbeatSchema.safeParse(JSON.parse(body.toString("utf8")));
      if (!parsed.success) return this.json(res, 400, { error: parsed.error.issues[0]?.message });
      this.heartbeats.push(parsed.data);
      return this.json(res, 200, { serverTime: new Date().toISOString(), ...this.heartbeatResponse });
    }

    const pkgMatch = /^\/packages\/([a-f0-9]{64})$/.exec(route);
    if (pkgMatch && req.method === "GET") {
      const bytes = this.packages.get(pkgMatch[1]!);
      this.packageDownloads.push(pkgMatch[1]!);
      if (!bytes) return this.json(res, 404, { error: "unknown package" });
      res.writeHead(200, { "content-type": "application/octet-stream", "content-length": String(bytes.length) });
      res.end(bytes);
      return;
    }

    if (route === "/audit" && req.method === "GET") {
      const after = BigInt(url.searchParams.get("after") ?? "0");
      const limit = Number(url.searchParams.get("limit") ?? "500");
      const records = this.audit.filter((r) => BigInt(r.seq) > after && !this.auditWithheld.has(r.seq)).slice(0, limit);
      const head = this.audit.length ? { seq: this.audit[this.audit.length - 1]!.seq, hash: this.audit[this.audit.length - 1]!.hash } : null;
      return this.json(res, 200, { records, head });
    }

    return this.json(res, 404, { error: "no route" });
  }
}
