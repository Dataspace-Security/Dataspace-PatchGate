// PatchGate job signer — the ONLY place the job-signing private keys live in the hosted deployment.
//
// Tiny, dependency-free Node HTTP service on an internal-only Docker network ("signer"); only web-1/web-2
// can reach it, with a shared bearer token. It signs canonical job envelopes (patchgate-web
// src/lib/connector/protocol.ts) after validating them, rate-limits per bank and globally, and writes one
// JSON audit line per decision. Keys are PER BANK: <SIGNER_KEY_DIR>/<tenantId>.pem, fallback default.pem
// (unless SIGNER_REQUIRE_TENANT_KEY=true), so one bank's key compromise does not affect the others.
//
// API (all JSON; Authorization: Bearer <token> except /healthz)
//   GET  /healthz                         -> {"status":"ok","keys":<n>}
//   GET  /v1/public-key[?tenantId=<id>]   -> {tenantId, keyId, publicKey, fingerprint}
//   POST /v1/sign  {"envelope":{...}}     -> {signature, keyId, publicKey, fingerprint}
// SIGHUP reloads keys (rotation without restart).
//
// KEEP IN SYNC with patchgate-web/src/lib/connector/protocol.ts (canonicalJson, JobEnvelope fields,
// job types, MAX_JOB_LIFETIME_MS, MAX_CLOCK_SKEW_MS). This file must not import anything from the app:
// it is copied verbatim into its own image. deploy/signer/server.test.mjs pins the shared rules.

import { createHash, createPrivateKey, createPublicKey, sign, timingSafeEqual } from "node:crypto";
import { appendFileSync, readFileSync, readdirSync } from "node:fs";
import { createServer } from "node:http";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

// ------------------------------------------------------------------ shared rules (copied from protocol.ts)
export const JOB_TYPES = Object.freeze([
  "SYNC_AGENTS",
  "SCAN",
  "COLLECT",
  "DEPLOY_WINDOWS",
  "DEPLOY_PACKAGE",
  "RESET_APPROVALS",
  "CACHE_PACKAGE",
  "WU_SCAN",
  "WU_INSTALL",
  "TACTICAL_AUDIT_SYNC",
  "TACTICAL_GUARD_SYNC",
]);
export const MAX_JOB_LIFETIME_MS = 72 * 3_600_000;
export const MAX_CLOCK_SKEW_MS = 5 * 60_000;
const ENVELOPE_KEYS = ["connectorId", "expiresAt", "id", "notBefore", "payload", "tenantId", "type", "v"];
const TENANT_ID_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/; // also the key file name: no path traversal possible
const CONNECTOR_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
const JOB_ID_RE = /^job_[A-Za-z0-9_-]{16,64}$/;
const SPKI_ED25519_PREFIX_LEN = 12;

export function canonicalJson(value) {
  if (value === null || typeof value !== "object") {
    if (typeof value === "number" && !Number.isFinite(value)) throw new Error("non-finite number");
    if (value === undefined) throw new Error("undefined is not allowed");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(",")}}`;
}

const isPlainObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

function isoMs(s) {
  if (typeof s !== "string") return NaN;
  const ms = Date.parse(s);
  // Must be the exact toISOString() form the app stores (signature covers the string).
  return Number.isFinite(ms) && new Date(ms).toISOString() === s ? ms : NaN;
}

/** Envelope validation: same envelope rules the connector applies (payload schemas: app + connector). */
export function validateEnvelope(env, nowMs, maxScheduleMs) {
  if (!isPlainObject(env)) return "envelope must be an object";
  const keys = Object.keys(env).sort();
  if (keys.length !== ENVELOPE_KEYS.length || keys.some((k, i) => k !== ENVELOPE_KEYS[i])) return "envelope has unexpected or missing fields";
  if (env.v !== 1) return "unsupported job version";
  if (typeof env.id !== "string" || !JOB_ID_RE.test(env.id)) return "invalid job id";
  if (typeof env.tenantId !== "string" || !TENANT_ID_RE.test(env.tenantId)) return "invalid tenantId";
  if (typeof env.connectorId !== "string" || !CONNECTOR_ID_RE.test(env.connectorId)) return "invalid connectorId";
  if (!JOB_TYPES.includes(env.type)) return "unknown job type";
  if (!isPlainObject(env.payload)) return "payload must be an object";
  const nb = isoMs(env.notBefore);
  const exp = isoMs(env.expiresAt);
  if (!Number.isFinite(nb) || !Number.isFinite(exp)) return "notBefore/expiresAt must be ISO-8601 (toISOString)";
  if (exp <= nb) return "job would expire before it may start";
  if (exp - nb > MAX_JOB_LIFETIME_MS) return "job lifetime too long";
  if (exp <= nowMs) return "job already expired";
  if (nb > nowMs + maxScheduleMs) return "notBefore too far in the future";
  try {
    canonicalJson(env);
  } catch (err) {
    return `envelope not canonicalisable: ${err.message}`;
  }
  return null;
}

// ------------------------------------------------------------------ keys
function rawPublicKey(privateKey) {
  const der = createPublicKey(privateKey).export({ format: "der", type: "spki" });
  return Buffer.from(der.subarray(SPKI_ED25519_PREFIX_LEN)).toString("base64");
}
export const fingerprint = (rawB64) => createHash("sha256").update(Buffer.from(rawB64, "base64")).digest("hex");

/** Load <dir>/default.pem and <dir>/<tenantId>.pem (Ed25519 PKCS#8). Other files are ignored. */
export function loadKeys(dir) {
  const keys = new Map();
  for (const name of readdirSync(dir)) {
    const m = /^(.+)\.pem$/.exec(name);
    if (!m || name.endsWith(".pub.pem")) continue;
    const keyId = m[1];
    if (keyId !== "default" && !TENANT_ID_RE.test(keyId)) continue;
    const privateKey = createPrivateKey(readFileSync(join(dir, name), "utf8"));
    if (privateKey.asymmetricKeyType !== "ed25519") throw new Error(`${name}: expected an Ed25519 private key`);
    const publicKey = rawPublicKey(privateKey);
    keys.set(keyId, { keyId, privateKey, publicKey, fingerprint: fingerprint(publicKey) });
  }
  return keys;
}

// ------------------------------------------------------------------ server
const MAX_BODY_BYTES = 4 * 1024 * 1024;

function tokenDigest(t) {
  return createHash("sha256").update(t).digest();
}

/**
 * Create the signer HTTP server (not listening). Options:
 *   token, keyDir, ratePerTenantPerMin, ratePerMin, maxScheduleMs, requireTenantKey, audit(line), now()
 */
export function createSigner(opts) {
  if (typeof opts.token !== "string" || opts.token.length < 32) throw new Error("signer token must be >= 32 chars");
  const tokenHash = tokenDigest(opts.token);
  const now = opts.now ?? Date.now;
  const audit = opts.audit ?? ((line) => process.stdout.write(`${line}\n`));
  const perTenant = opts.ratePerTenantPerMin ?? 600;
  const global = opts.ratePerMin ?? 3000;
  const maxScheduleMs = opts.maxScheduleMs ?? 90 * 24 * 3_600_000;
  let keys = loadKeys(opts.keyDir);
  if (keys.size === 0) throw new Error(`no signing keys in ${opts.keyDir} (expected default.pem and/or <tenantId>.pem)`);

  let window = { start: 0, total: 0, byTenant: new Map() };
  function allow(tenantId) {
    const t = now();
    if (t - window.start >= 60_000) window = { start: t, total: 0, byTenant: new Map() };
    const n = window.byTenant.get(tenantId) ?? 0;
    if (window.total >= global || n >= perTenant) return false;
    window.total += 1;
    window.byTenant.set(tenantId, n + 1);
    return true;
  }

  function keyFor(tenantId) {
    if (tenantId && keys.has(tenantId)) return keys.get(tenantId);
    if (opts.requireTenantKey && tenantId) return undefined;
    return keys.get("default");
  }

  function log(level, msg, fields) {
    audit(JSON.stringify({ ts: new Date(now()).toISOString(), level, msg, component: "signer", ...fields }));
  }

  const send = (res, status, body) => {
    const json = JSON.stringify(body);
    res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store", "content-length": Buffer.byteLength(json) });
    res.end(json);
  };

  function authorized(req) {
    const h = req.headers.authorization ?? "";
    const m = /^Bearer (.+)$/.exec(h);
    return Boolean(m) && timingSafeEqual(tokenDigest(m[1]), tokenHash);
  }

  async function readBody(req) {
    const chunks = [];
    let size = 0;
    for await (const c of req) {
      size += c.length;
      if (size > MAX_BODY_BYTES) throw Object.assign(new Error("body too large"), { status: 413 });
      chunks.push(c);
    }
    return Buffer.concat(chunks).toString("utf8");
  }

  async function handle(req, res) {
    const url = new URL(req.url ?? "/", "http://signer");
    const client = req.socket.remoteAddress;
    if (req.method === "GET" && url.pathname === "/healthz") return send(res, 200, { status: "ok", keys: keys.size });
    if (!authorized(req)) {
      log("warn", "signer.denied", { client, path: url.pathname, reason: "unauthorized" });
      return send(res, 401, { error: "unauthorized" });
    }

    if (req.method === "GET" && url.pathname === "/v1/public-key") {
      const tenantId = url.searchParams.get("tenantId") ?? undefined;
      if (tenantId !== undefined && !TENANT_ID_RE.test(tenantId)) return send(res, 400, { error: "invalid tenantId" });
      const k = keyFor(tenantId);
      if (!k) return send(res, 404, { error: "no key for tenant" });
      return send(res, 200, { tenantId: tenantId ?? null, keyId: k.keyId, publicKey: k.publicKey, fingerprint: k.fingerprint });
    }

    if (req.method === "POST" && url.pathname === "/v1/sign") {
      let parsed;
      try {
        parsed = JSON.parse(await readBody(req));
      } catch (err) {
        const status = err.status ?? 400;
        log("warn", "signer.denied", { client, reason: status === 413 ? "body too large" : "invalid json" });
        return send(res, status, { error: status === 413 ? "body too large" : "invalid json" });
      }
      const env = isPlainObject(parsed) ? parsed.envelope : undefined;
      const base = isPlainObject(env)
        ? { client, jobId: String(env.id ?? ""), tenantId: String(env.tenantId ?? ""), connectorId: String(env.connectorId ?? ""), type: String(env.type ?? "") }
        : { client };
      const problem = validateEnvelope(env, now(), maxScheduleMs);
      if (problem) {
        log("warn", "signer.denied", { ...base, reason: problem });
        return send(res, 422, { error: problem });
      }
      if (!allow(env.tenantId)) {
        log("warn", "signer.denied", { ...base, reason: "rate limited" });
        return send(res, 429, { error: "rate limited" });
      }
      const k = keyFor(env.tenantId);
      if (!k) {
        log("warn", "signer.denied", { ...base, reason: "no key for tenant" });
        return send(res, 404, { error: "no key for tenant" });
      }
      const message = canonicalJson(env);
      const signature = sign(null, Buffer.from(message), k.privateKey).toString("base64");
      log("info", "signer.signed", {
        ...base,
        keyId: k.keyId,
        keyFingerprint: k.fingerprint,
        notBefore: env.notBefore,
        expiresAt: env.expiresAt,
        envelopeSha256: createHash("sha256").update(message).digest("hex"),
      });
      return send(res, 200, { signature, keyId: k.keyId, publicKey: k.publicKey, fingerprint: k.fingerprint });
    }
    return send(res, 404, { error: "not found" });
  }

  const server = createServer((req, res) => {
    handle(req, res).catch((err) => {
      log("error", "signer.error", { error: err instanceof Error ? err.message : "unknown" });
      if (!res.headersSent) send(res, 500, { error: "internal error" });
      else res.destroy();
    });
  });
  server.headersTimeout = 10_000;
  server.requestTimeout = 30_000;
  server.reloadKeys = () => {
    const next = loadKeys(opts.keyDir);
    if (next.size === 0) throw new Error("reload: no keys found; keeping the previous set");
    keys = next;
    log("info", "signer.keys_loaded", { keys: [...keys.values()].map((k) => ({ keyId: k.keyId, fingerprint: k.fingerprint })) });
  };
  server.keyCount = () => keys.size;
  return server;
}

// ------------------------------------------------------------------ main
function main() {
  const e = process.env;
  const tokenFile = e.SIGNER_TOKEN_FILE ?? "/run/secrets/job_signer_token";
  const auditFile = e.SIGNER_AUDIT_FILE; // optional: also append audit lines to a file (volume)
  const audit = (line) => {
    process.stdout.write(`${line}\n`);
    if (auditFile) appendFileSync(auditFile, `${line}\n`, { mode: 0o600 });
  };
  const server = createSigner({
    token: readFileSync(tokenFile, "utf8").trim(),
    keyDir: e.SIGNER_KEY_DIR ?? "/run/job-keys",
    ratePerTenantPerMin: Number(e.SIGNER_RATE_PER_TENANT_PER_MIN ?? 600),
    ratePerMin: Number(e.SIGNER_RATE_PER_MIN ?? 3000),
    maxScheduleMs: Number(e.SIGNER_MAX_SCHEDULE_DAYS ?? 90) * 24 * 3_600_000,
    requireTenantKey: e.SIGNER_REQUIRE_TENANT_KEY === "true",
    audit,
  });
  server.reloadKeys(); // logs the key fingerprints at start
  process.on("SIGHUP", () => {
    try {
      server.reloadKeys();
    } catch (err) {
      audit(JSON.stringify({ ts: new Date().toISOString(), level: "error", msg: "signer.reload_failed", component: "signer", error: err.message }));
    }
  });
  const stop = () => server.close(() => process.exit(0));
  process.on("SIGTERM", stop);
  process.on("SIGINT", stop);
  const port = Number(e.SIGNER_PORT ?? 8080);
  server.listen(port, "0.0.0.0", () => audit(JSON.stringify({ ts: new Date().toISOString(), level: "info", msg: "signer.listening", component: "signer", port })));
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  try {
    main();
  } catch (err) {
    process.stderr.write(`${JSON.stringify({ ts: new Date().toISOString(), level: "error", msg: "signer.start_failed", component: "signer", error: err.message })}\n`);
    process.exit(1);
  }
}
