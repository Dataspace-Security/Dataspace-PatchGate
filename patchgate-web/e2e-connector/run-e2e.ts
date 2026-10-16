/**
 * REAL end-to-end run of the connector pipeline:
 *   PatchGate (`next dev -p 3300`, AUTH_MODE=dev, DB patchgate_test_conn)
 *   ⇄ the BUILT patchgate-connector (dist/patchgate-connector.mjs, init + run)
 *   ⇄ a fake Tactical RMM (fake-tactical.ts) whose "PCs" download from the connector's site cache.
 *
 * Proves: enrol → SYNC_AGENTS → COLLECT → approved CR (maker-checker over the real API) → CACHE_PACKAGE →
 * DEPLOY_PACKAGE → result → confirm via COLLECT → deployments SUCCEEDED, CR COMPLETED; and that a
 * tampered or replayed signed request is rejected, and a revoked connector is refused.
 *
 *   cd patchgate-web && npx tsx e2e-connector/run-e2e.ts
 * Output: e2e-connector/out/{result.json,next.log,connector.log}. Stops every process it started.
 */
import { execFileSync, spawn, type ChildProcess } from "node:child_process";
import { createPrivateKey, randomBytes } from "node:crypto";
import { createWriteStream, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { PrismaClient } from "@prisma/client";
import { HEADERS, sha256Hex, signRequest } from "../src/lib/connector/protocol";
import { TENANT_A, TENANT_B, resetDb } from "../src/test/helpers";
import { FakeTactical } from "./fake-tactical";

const HERE = dirname(fileURLToPath(import.meta.url));
const WEB = resolve(HERE, "..");
const CONNECTOR = resolve(WEB, "..", "patchgate-connector");
const OUT = join(HERE, "out");
const PORT = 3300;
const BASE = `http://localhost:${PORT}`;
const DB = process.env.E2E_DATABASE_URL ?? "postgresql://patchgate:patchgate-dev-only@127.0.0.1:55432/patchgate_test_conn?schema=public";
if (!/patchgate_test_conn/.test(DB)) throw new Error("refusing to run: E2E_DATABASE_URL must point at patchgate_test_conn");

const WORKER_TOKEN = "w".repeat(40);
const TACTICAL_KEY = `tactical-e2e-${randomBytes(12).toString("hex")}`;
const ADMIN = "admin@pg.e2e";
const OPERATOR = "operator@pg.e2e";
const APPROVER = "approver@bank-a.e2e";
const SEVEN_ZIP_MSI = Buffer.from(`pretend 7-Zip 24.08 MSI ${"x".repeat(4096)}`);

const results: { step: string; ok: boolean; detail?: unknown }[] = [];
const procs: ChildProcess[] = [];
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function record(step: string, ok: boolean, detail?: unknown): void {
  results.push({ step, ok, detail });
  process.stdout.write(`${ok ? "PASS" : "FAIL"}  ${step}${detail !== undefined ? `  ${JSON.stringify(detail)}` : ""}\n`);
  if (!ok) throw new Error(`step failed: ${step}`);
}

function freePort(): Promise<number> {
  return new Promise((res, rej) => {
    const s = createServer();
    s.once("error", rej);
    s.listen(0, "127.0.0.1", () => {
      const p = (s.address() as AddressInfo).port;
      s.close(() => res(p));
    });
  });
}

function startProcess(name: string, cmd: string, args: string[], opts: { cwd: string; env: NodeJS.ProcessEnv }): ChildProcess {
  const log = createWriteStream(join(OUT, `${name}.log`));
  const p = spawn(cmd, args, { cwd: opts.cwd, env: opts.env, shell: process.platform === "win32", windowsHide: true });
  p.stdout?.pipe(log);
  p.stderr?.pipe(log);
  procs.push(p);
  return p;
}

function killTree(p: ChildProcess): void {
  if (p.exitCode !== null || !p.pid) return;
  try {
    if (process.platform === "win32") execFileSync("taskkill", ["/pid", String(p.pid), "/T", "/F"], { stdio: "ignore" });
    else p.kill("SIGTERM");
  } catch {
    // already gone
  }
}

async function until<T>(what: string, fn: () => Promise<T | null | undefined | false>, timeoutMs: number, tick = true): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (tick) await workerTick();
    const v = await fn();
    if (v) return v;
    if (Date.now() > deadline) throw new Error(`timed out waiting for: ${what}`);
    await sleep(1500);
  }
}

async function workerTick(): Promise<void> {
  const res = await fetch(`${BASE}/api/worker/tick`, { method: "POST", headers: { "x-worker-token": WORKER_TOKEN } });
  if (!res.ok) throw new Error(`worker tick HTTP ${res.status}`);
}

async function api<T>(method: string, path: string, user: string, body?: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: { "content-type": "application/json", origin: BASE, cookie: `pg_dev_user=${user}; pg_tenant=${TENANT_A}` },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const json = (await res.json().catch(() => null)) as { success?: boolean; data?: T; error?: string } | null;
  if (!res.ok || !json?.success) throw new Error(`${method} ${path} → ${res.status} ${json?.error ?? ""}`);
  return json.data as T;
}

async function seed(prisma: PrismaClient, repoDir: string) {
  await resetDb(prisma);
  await prisma.user.createMany({
    data: [
      { upn: ADMIN, name: "Platform admin", role: "ADMIN" },
      { upn: OPERATOR, name: "Platform operator", role: "OPERATOR" },
      { upn: APPROVER, name: "Bank A approver", role: "APPROVER", tenantId: TENANT_A },
    ],
  });
  const repoPath = "pkgs/7zip/24.08/7z2408-x64.msi";
  mkdirSync(join(repoDir, "pkgs", "7zip", "24.08"), { recursive: true });
  writeFileSync(join(repoDir, ...repoPath.split("/")), SEVEN_ZIP_MSI);
  const app = await prisma.app.create({ data: { wingetId: "7zip.7zip", displayName: "7-Zip", inventoryMatch: "^7-Zip", expectedPublisher: "O=Igor Pavlov", allowedDomains: [] } });
  const v = await prisma.appVersion.create({
    data: {
      appId: app.id, version: "24.08", installerUrl: "https://github.com/ip7z/7zip/releases/download/24.08/7z2408-x64.msi", sha256: sha256Hex(SEVEN_ZIP_MSI),
      silentArgs: "", verification: "VERIFIED", repoPath, availableAt: new Date(Date.now() - 60_000), signerOrg: "Igor Pavlov",
    },
  });
  const patch = await prisma.patch.create({ data: { kind: "THIRD_PARTY", externalId: "7zip.7zip@24.08", title: "7-Zip 24.08", appVersionId: v.id } });
  await prisma.tenantApp.create({ data: { tenantId: TENANT_A, appId: app.id, enabledBy: ADMIN } });
  const ring = await prisma.ring.create({ data: { tenantId: TENANT_A, name: "Ring0-Test", wsusGroup: "Ring0", order: 0 } });
  // A different bank with an agent id of its own: never touched by bank A's connector.
  await prisma.endpoint.create({ data: { tenantId: TENANT_B, tacticalAgentId: "agentBANKB00001", hostname: "B-PC" } });
  return { patchId: patch.id, ringId: ring.id, sha256: sha256Hex(SEVEN_ZIP_MSI) };
}

interface SignedCall {
  method: string;
  path: string;
  body: string;
  headers: Record<string, string>;
}

function signedCall(connectorId: string, keyPem: string, method: string, path: string, body = "", signPath = path, signBody = body): SignedCall {
  const ts = String(Date.now());
  const nonce = randomBytes(16).toString("base64url");
  const sig = signRequest(createPrivateKey(keyPem), method, signPath, ts, nonce, signBody);
  return {
    method,
    path,
    body,
    headers: { [HEADERS.connector]: connectorId, [HEADERS.timestamp]: ts, [HEADERS.nonce]: nonce, [HEADERS.signature]: sig, "content-type": "application/json" },
  };
}

async function send(c: SignedCall): Promise<{ status: number; json: unknown }> {
  const res = await fetch(`${BASE}${c.path}`, { method: c.method, headers: c.headers, body: c.method === "GET" ? undefined : c.body });
  return { status: res.status, json: await res.json().catch(() => null) };
}

async function main(): Promise<void> {
  rmSync(OUT, { recursive: true, force: true });
  mkdirSync(OUT, { recursive: true });
  const work = mkdtempSync(join(tmpdir(), "pg-e2e-conn-"));
  const repoDir = join(work, "repo");
  mkdirSync(repoDir, { recursive: true });
  const prisma = new PrismaClient({ datasourceUrl: DB });
  const fake = new FakeTactical(TACTICAL_KEY);

  try {
    const fx = await seed(prisma, repoDir);
    fake.addAgent({ agent_id: "agentE2E000001", hostname: "PC-01", software: [{ name: "7-Zip 23.01 (x64)", version: "23.01", publisher: "Igor Pavlov" }] });
    fake.addAgent({ agent_id: "agentE2E000002", hostname: "PC-02", software: [{ name: "7-Zip 23.01 (x64)", version: "23.01", publisher: "Igor Pavlov" }] });
    fake.installs.set("7zip.7zip", { name: "7-Zip 24.08 (x64)", version: "24.08", publisher: "Igor Pavlov" });
    const tacticalUrl = await fake.start();

    // ---- PatchGate (only this agent runs next dev; port 3300) ----
    startProcess("next", "npx", ["next", "dev", "-p", String(PORT)], {
      cwd: WEB,
      env: {
        ...process.env,
        DATABASE_URL: DB,
        AUTH_MODE: "dev",
        DEV_USER_UPN: "",
        REPO_DIR: repoDir,
        PUBLIC_BASE_URL: BASE,
        TACTICAL_API_URL: "http://127.0.0.1:9/api", // legacy direct link: unused (bank A has a connector)
        TACTICAL_API_KEY: "k".repeat(32),
        PATCH_REPO_URL: `${BASE}/repo`,
        AUDIT_HMAC_KEY: "h".repeat(40),
        WORKER_TOKEN,
        AUTH_ENC_KEY: "cd".repeat(32),
        LOG_LEVEL: "warn",
      },
    });
    await until("PatchGate /api/health", async () => (await fetch(`${BASE}/api/health`).catch(() => null))?.ok, 240_000, false);
    record("PatchGate dev server up on :3300", true);

    // ---- Enrolment code (platform admin, real API) ----
    const created = await api<{ code: string; initCommand: string }>("POST", "/api/connector/admin/enrollments", ADMIN, { tenantId: TENANT_A, name: "Head office DC" });
    record("enrolment code created", /^[A-Z0-9]{4}(-[A-Z0-9]{4}){4}$/.test(created.code) && created.initCommand.includes(`--server ${BASE}`), { initCommand: created.initCommand.split("\n")[0].replace(created.code, "<code>") });

    // ---- Build + init + run the REAL connector ----
    execFileSync("npm", ["run", "build"], { cwd: CONNECTOR, stdio: "ignore", shell: process.platform === "win32" });
    const bin = join(CONNECTOR, "dist", "patchgate-connector.mjs");
    const stateDir = join(work, "connector-state");
    mkdirSync(stateDir, { recursive: true });
    const apiKeyFile = join(work, "tactical-api-key");
    writeFileSync(apiKeyFile, TACTICAL_KEY);
    const cachePort = await freePort();
    const cfgPath = join(work, "connector.json");
    writeFileSync(
      cfgPath,
      JSON.stringify(
        {
          stateDir,
          logLevel: "info",
          insecureDev: true,
          tactical: { url: tacticalUrl, apiKeyFile, installScriptId: 7, timeoutMs: 15_000, statusIntervalSec: 5 },
          cache: { baseUrl: `http://127.0.0.1:${cachePort}/repo`, listenHost: "127.0.0.1", port: cachePort, minFreeBytes: 0 },
          limits: { heartbeatIntervalSec: 5, pollWaitSec: 5, maxConcurrentInstalls: 10 },
        },
        null,
        2,
      ),
    );
    execFileSync(process.execPath, [bin, "init", "--config", cfgPath, "--server", BASE, "--insecure-dev"], { env: { ...process.env, PATCHGATE_ENROLL_CODE: created.code }, stdio: "ignore" });
    const cfg = JSON.parse(readFileSync(cfgPath, "utf8")) as { identity: { connectorId: string; tenantId: string; privateKeyFile: string; jobSigningPublicKey: string } };
    const connectorId = cfg.identity.connectorId;
    record("connector built, enrolled (init) and pinned the job key", cfg.identity.tenantId === TENANT_A && cfg.identity.jobSigningPublicKey.length === 44, { connectorId });

    // a used code cannot enrol a second connector
    const second = await fetch(`${BASE}/api/connector/v1/enroll`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ code: created.code, publicKey: `${"A".repeat(43)}=`, version: "1.0.0", proof: "x" }) });
    record("enrolment code is single use", second.status === 403, { status: second.status });

    startProcess("connector", process.execPath, [bin, "run", "--config", cfgPath], { cwd: work, env: process.env });

    // ---- SYNC_AGENTS → endpoints ----
    const endpoints = await until(
      "SYNC_AGENTS created both endpoints",
      async () => {
        const eps = await prisma.endpoint.findMany({ where: { tenantId: TENANT_A, connectorId }, orderBy: { hostname: "asc" } });
        return eps.length === 2 ? eps : null;
      },
      120_000,
    );
    const hb = await prisma.connector.findUniqueOrThrow({ where: { id: connectorId } });
    record("SYNC_AGENTS → endpoints (bank A only), heartbeat stored", (await prisma.endpoint.count({ where: { tenantId: TENANT_B } })) === 1 && hb.heartbeat !== null, {
      endpoints: endpoints.map((e) => e.hostname),
      cacheBaseUrl: hb.cacheBaseUrl,
    });

    // ---- LAN limits (platform admin): small waves for this site; the connector learns them by heartbeat ----
    const limits = await api<{ maxConcurrentInstalls: number }>("PATCH", `/api/connector/admin/connectors/${connectorId}`, ADMIN, { maxConcurrentInstalls: 2, bandwidthLimitMbps: 100 });
    record("LAN limits set by the platform admin (audited)", limits.maxConcurrentInstalls === 2);

    // ---- COLLECT → software inventory + agent version ----
    await until(
      "COLLECT ingested inventory",
      async () => (await prisma.endpoint.count({ where: { tenantId: TENANT_A, lastScanAt: { not: null } } })) === 2 && (await prisma.installedSoftware.count({ where: { tenantId: TENANT_A } })) === 2,
      120_000,
    );
    const needed = await prisma.endpointPatchState.count({ where: { tenantId: TENANT_A, status: "NEEDED", patchId: fx.patchId } });
    record("COLLECT → inventory ingested; 7-Zip 24.08 NEEDED on both PCs", needed === 2, { needed });

    // ---- Maker-checker over the real API ----
    for (const e of endpoints) await api("PATCH", `/api/endpoints/${e.id}`, OPERATOR, { ringId: fx.ringId });
    const cr = await api<{ id: string }>("POST", "/api/change-requests", OPERATOR, { title: "7-Zip 24.08 via connector", ringId: fx.ringId, patchIds: [fx.patchId] });
    await api("POST", `/api/change-requests/${cr.id}/submit`, OPERATOR, {});
    await api("POST", `/api/change-requests/${cr.id}/approve`, APPROVER, {});
    await api("POST", `/api/change-requests/${cr.id}/deploy`, APPROVER, {});
    record("change request created (maker), approved (bank checker), deploying", (await prisma.changeRequest.findUniqueOrThrow({ where: { id: cr.id } })).status === "DEPLOYING");

    // ---- CACHE_PACKAGE → DEPLOY_PACKAGE → result → confirm → SUCCEEDED ----
    await until("site cache holds the package", async () => (await prisma.connectorJob.count({ where: { type: "CACHE_PACKAGE", status: "SUCCEEDED", processedAt: { not: null } } })) === 1, 120_000);
    record("CACHE_PACKAGE: one download for the site, verified", true, {
      downloads: await prisma.auditEvent.count({ where: { action: "connector.package_downloaded", tenantId: TENANT_A } }),
    });
    await until(
      "deployments SUCCEEDED and CR COMPLETED",
      async () => (await prisma.changeRequest.findUniqueOrThrow({ where: { id: cr.id } })).status === "COMPLETED",
      240_000,
    );
    const deps = await prisma.deployment.findMany({ where: { changeRequestId: cr.id }, select: { status: true } });
    const installs = await prisma.connectorJob.findMany({ where: { type: "DEPLOY_PACKAGE" }, select: { status: true } });
    record("DEPLOY_PACKAGE ran on both PCs from the site cache; deployments SUCCEEDED; CR COMPLETED", deps.every((d) => d.status === "SUCCEEDED") && fake.scriptRuns.filter((r) => r.result === "OK").length === 2, {
      deployments: deps.map((d) => d.status),
      installJobs: installs.map((j) => j.status),
      pcDownloads: fake.scriptRuns.map((r) => `${r.agentId}: ${r.env.PG_REPO_URL} → ${r.result}`),
      cacheJobs: await prisma.connectorJob.count({ where: { type: "CACHE_PACKAGE" } }),
    });

    // ---- Tampered / replayed requests ----
    const keyPem = readFileSync(cfg.identity.privateKeyFile, "utf8");
    const okCall = signedCall(connectorId, keyPem, "GET", "/api/connector/v1/audit?after=0&limit=3");
    const ok = await send(okCall);
    const replay = await send(okCall);
    const tamperedQuery = await send(signedCall(connectorId, keyPem, "GET", "/api/connector/v1/audit?after=0&limit=500", "", "/api/connector/v1/audit?after=0&limit=3"));
    const hbBody = JSON.stringify({ version: "9.9.9", cache: { files: 0, bytes: 0 }, tactical: { reachable: true } });
    const tamperedBody = await send(signedCall(connectorId, keyPem, "POST", "/api/connector/v1/heartbeat", hbBody.replace("9.9.9", "6.6.6"), "/api/connector/v1/heartbeat", hbBody));
    const unsigned = await fetch(`${BASE}/api/connector/v1/jobs?wait=0`);
    const relay = ok.json as { records: { action: string }[] };
    record("valid signed request accepted; relay returns this bank's chain", ok.status === 200 && relay.records.length === 3, { actions: relay.records.map((r) => r.action) });
    record("replayed request rejected", replay.status === 401, { status: replay.status });
    record("tampered query rejected", tamperedQuery.status === 401, { status: tamperedQuery.status });
    record("tampered body rejected", tamperedBody.status === 401, { status: tamperedBody.status });
    record("unsigned request rejected", unsigned.status === 401, { status: unsigned.status });

    // ---- UI renders (platform admin: all banks + admin actions; bank user: read-only own bank; dashboard card) ----
    const page = async (path: string, user: string) => {
      const res = await fetch(`${BASE}${path}`, { headers: { cookie: `pg_dev_user=${user}; pg_tenant=${TENANT_A}` } });
      return { status: res.status, html: await res.text() };
    };
    const adminPage = await page("/connectors", ADMIN);
    const bankPage = await page("/connectors", APPROVER);
    const dash = await page("/", APPROVER);
    record(
      "UI: /connectors (admin + bank read-only) and dashboard connector card render",
      adminPage.status === 200 && adminPage.html.includes("Head office DC") && adminPage.html.includes("Enrol a site connector") &&
        bankPage.status === 200 && bankPage.html.includes("Head office DC") && !bankPage.html.includes("Enrol a site connector") &&
        dash.status === 200 && dash.html.includes("Site connectors"),
      { admin: adminPage.status, bank: bankPage.status, dashboard: dash.status },
    );

    // ---- Revoke: immediately refused ----
    await api("POST", `/api/connector/admin/connectors/${connectorId}/revoke`, ADMIN, { reason: "e2e" });
    const afterRevoke = await send(signedCall(connectorId, keyPem, "GET", "/api/connector/v1/jobs?wait=0"));
    record("revoked connector refused (403)", afterRevoke.status === 403, { status: afterRevoke.status });

    const audit = await prisma.auditEvent.findMany({ where: { tenantId: TENANT_A }, orderBy: { seq: "asc" }, select: { action: true } });
    record("bank A audit chain records the whole flow", ["connector.enrolled", "connector.agents_synced", "change_request.approve", "deployment.succeeded", "connector.revoked"].every((a) => audit.some((e) => e.action === a)), {
      events: audit.length,
    });
  } finally {
    for (const p of procs.reverse()) killTree(p);
    await fake.stop();
    await prisma.$disconnect();
    writeFileSync(join(OUT, "result.json"), JSON.stringify({ at: new Date().toISOString(), passed: results.filter((r) => r.ok).length, results }, null, 2));
    rmSync(work, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  }
}

main().then(
  () => {
    process.stdout.write(`\nE2E PASSED (${results.length} checks)\n`);
    process.exit(0);
  },
  (err: unknown) => {
    process.stderr.write(`\nE2E FAILED: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`);
    process.exit(1);
  },
);
