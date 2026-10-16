import "server-only";
import { createHash, createPublicKey, generateKeyPairSync, verify, type KeyObject } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { env } from "@/lib/env";
import { log } from "@/lib/log";
import { canonicalJson, privateKeyFromPem, publicKeyFromRaw, rawFromPublicKey, signJob, type JobEnvelope, type SignedJob } from "./protocol";

/**
 * PatchGate's job signer (Ed25519). Every job envelope is signed; connectors pin the raw public key at
 * enrolment (and its fingerprint at init) and refuse anything else (ARCHITECTURE-HOSTED §3 "Job authenticity").
 *
 * Pluggable via JOB_SIGNER (src/lib/env.ts):
 *  - "file" (default; lab/dev, single-host fallback): the private key is read from JOB_SIGNING_KEY_FILE into
 *    this process. One key for all banks. Development/test only: when JOB_SIGNING_KEY_FILE is unset, a key
 *    is created once under REPO_DIR/.keys (never served: the repository and package endpoints only serve
 *    pkgs/, tactical/ and winupdate/).
 *  - "remote" (production): the private keys live ONLY in the signer service (deploy/signer/server.mjs) on
 *    an internal Docker network. It holds one key PER BANK (fallback: a default key), validates every
 *    envelope, rate-limits and audit-logs each signature. This process holds a bearer token, never a key.
 *  - "disabled": this container never signs (e.g. the fetcher); every signing call fails closed.
 *
 * API
 *  - signJobEnvelope(envelope)   async, all modes — the ONLY way new code should sign jobs.
 *  - jobSigningPublicKey(tenant) async, all modes — the public key a bank's connectors must pin.
 *  - jobSigningKey(tenant?)      sync, "file" mode only (kept for existing callers/tests); throws otherwise.
 */

export interface JobSigningKey {
  privateKey: KeyObject;
  /** base64 of the raw 32-byte public key — what connectors pin */
  publicKeyRaw: string;
  file: string;
}

export type JobSignerMode = "file" | "remote" | "disabled";

const DEV_KEY_FILE = "job-signing-key.pem";
const REMOTE_TIMEOUT_MS = 5_000;
/** Public keys change only on rotation; re-read periodically so a rotated bank key is picked up. */
const PUBLIC_KEY_CACHE_MS = 5 * 60_000;
const TENANT_ID_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;
const RAW_KEY_RE = /^[A-Za-z0-9+/]{43}=$/;

let cached: JobSigningKey | undefined;
let cachedToken: string | undefined;
const publicKeyCache = new Map<string, { key: string; at: number }>();

export function jobSignerMode(): JobSignerMode {
  return env().JOB_SIGNER;
}

/** Fingerprint connectors pin at init (--job-key-fingerprint): SHA-256 (hex) of the raw 32-byte public key. */
export function jobKeyFingerprint(publicKeyRaw: string): string {
  return createHash("sha256").update(Buffer.from(publicKeyRaw, "base64")).digest("hex");
}

// ------------------------------------------------------------------------------------------ file mode

function devKeyFile(): string {
  return resolve(env().REPO_DIR, ".keys", DEV_KEY_FILE);
}

function createDevKey(file: string): void {
  mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
  const { privateKey } = generateKeyPairSync("ed25519");
  const pem = privateKey.export({ format: "pem", type: "pkcs8" }).toString();
  try {
    writeFileSync(file, pem, { flag: "wx", mode: 0o600 }); // wx: a concurrent creator wins, we read theirs
    log.warn("connector.job_key.created_dev_key", { file });
  } catch (err: unknown) {
    if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
  }
}

function readKeyFile(file: string): string | null {
  try {
    return readFileSync(file, "utf8");
  } catch (err: unknown) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw err;
  }
}

/**
 * "file" mode: load (and in development/test, create on first use) the job-signing key.
 * `tenantId` is accepted for API symmetry with jobSigningPublicKey(); file mode has ONE key for all banks.
 * Throws in "remote"/"disabled" mode (the private key is not available to this process).
 */
export function jobSigningKey(tenantId?: string): JobSigningKey {
  void tenantId; // file mode: one key for all banks
  const e = env();
  if (e.JOB_SIGNER !== "file") {
    throw new Error(`job-signing key is not available in this process (JOB_SIGNER=${e.JOB_SIGNER}); use signJobEnvelope()/jobSigningPublicKey()`);
  }
  if (cached) return cached;
  let file = e.JOB_SIGNING_KEY_FILE;
  let pem: string | null;
  if (file) {
    pem = readKeyFile(file);
    if (pem === null) throw new Error("JOB_SIGNING_KEY_FILE does not exist");
  } else {
    if (e.NODE_ENV === "production") throw new Error("JOB_SIGNING_KEY_FILE is required in production");
    file = devKeyFile();
    pem = readKeyFile(file);
    if (pem === null) {
      createDevKey(file);
      pem = readKeyFile(file);
      if (pem === null) throw new Error("could not create the development job-signing key");
    }
  }
  const privateKey = privateKeyFromPem(pem);
  cached = { privateKey, publicKeyRaw: rawFromPublicKey(createPublicKey(privateKey)), file };
  return cached;
}

// ------------------------------------------------------------------------------------------ remote mode

function signerToken(): string {
  if (cachedToken) return cachedToken;
  const file = env().JOB_SIGNER_TOKEN_FILE;
  if (!file) throw new Error("JOB_SIGNER_TOKEN_FILE is not configured");
  const token = readFileSync(file, "utf8").trim();
  if (token.length < 32) throw new Error("job signer token is too short (>= 32 chars)");
  cachedToken = token;
  return token;
}

function signerUrl(path: string): string {
  const base = env().JOB_SIGNER_URL;
  if (!base) throw new Error("JOB_SIGNER_URL is not configured");
  return `${base.replace(/\/+$/, "")}${path}`;
}

async function callSigner(path: string, init: { method: "GET" | "POST"; body?: string }): Promise<Record<string, unknown>> {
  let res: Response;
  try {
    res = await fetch(signerUrl(path), {
      method: init.method,
      body: init.body,
      headers: { authorization: `Bearer ${signerToken()}`, ...(init.body ? { "content-type": "application/json" } : {}) },
      signal: AbortSignal.timeout(REMOTE_TIMEOUT_MS),
      redirect: "error",
    });
  } catch (err: unknown) {
    log.error("connector.job_signer.unreachable", { path, error: err instanceof Error ? err.message : "unknown" });
    throw new Error("job signer unavailable");
  }
  const text = await res.text();
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    body = null;
  }
  if (!res.ok || !body || typeof body !== "object") {
    const reason = body && typeof body === "object" && typeof (body as { error?: unknown }).error === "string" ? (body as { error: string }).error : `HTTP ${res.status}`;
    log.error("connector.job_signer.rejected", { path, status: res.status, reason });
    throw new Error(`job signer rejected the request: ${reason}`);
  }
  return body as Record<string, unknown>;
}

function assertTenantId(tenantId: string): void {
  if (!TENANT_ID_RE.test(tenantId)) throw new Error("invalid tenant id for job signing");
}

async function remotePublicKey(tenantId: string | undefined, now: number): Promise<string> {
  const cacheKey = tenantId ?? "";
  const hit = publicKeyCache.get(cacheKey);
  if (hit && now - hit.at < PUBLIC_KEY_CACHE_MS) return hit.key;
  const q = tenantId ? `?tenantId=${encodeURIComponent(tenantId)}` : "";
  const body = await callSigner(`/v1/public-key${q}`, { method: "GET" });
  const key = body.publicKey;
  if (typeof key !== "string" || !RAW_KEY_RE.test(key)) throw new Error("job signer returned an invalid public key");
  publicKeyCache.set(cacheKey, { key, at: now });
  return key;
}

// ------------------------------------------------------------------------------------------ public API

/**
 * The job-signing public key (base64 raw 32 bytes) a bank's connectors must pin. With the remote signer
 * each bank may have its own key, so pass the bank's tenantId (enrolment response).
 */
export async function jobSigningPublicKey(tenantId?: string): Promise<string> {
  if (tenantId !== undefined) assertTenantId(tenantId);
  const mode = jobSignerMode();
  if (mode === "file") return jobSigningKey(tenantId).publicKeyRaw;
  if (mode === "disabled") throw new Error("job signing is disabled in this process (JOB_SIGNER=disabled)");
  return remotePublicKey(tenantId, Date.now());
}

/** Sign a canonical job envelope with the key of envelope.tenantId (remote) or the single file key. */
export async function signJobEnvelope(envelope: JobEnvelope): Promise<SignedJob> {
  assertTenantId(envelope.tenantId);
  const mode = jobSignerMode();
  if (mode === "file") return signJob(jobSigningKey(envelope.tenantId).privateKey, envelope);
  if (mode === "disabled") throw new Error("job signing is disabled in this process (JOB_SIGNER=disabled)");

  const body = await callSigner("/v1/sign", { method: "POST", body: JSON.stringify({ envelope }) });
  const { signature, publicKey } = body;
  if (typeof signature !== "string" || typeof publicKey !== "string" || !RAW_KEY_RE.test(publicKey)) {
    throw new Error("job signer returned a malformed response");
  }
  // Never store a signature the connector would reject: verify against the key the signer used, and that
  // key must be the bank's current public key (what its connectors pinned).
  let ok = false;
  try {
    ok = verify(null, Buffer.from(canonicalJson(envelope)), publicKeyFromRaw(publicKey), Buffer.from(signature, "base64"));
  } catch {
    ok = false;
  }
  if (!ok) throw new Error("job signer returned an invalid signature");
  const expected = await remotePublicKey(envelope.tenantId, Date.now());
  if (expected !== publicKey) {
    publicKeyCache.delete(envelope.tenantId); // rotated? re-read once
    if ((await remotePublicKey(envelope.tenantId, Date.now())) !== publicKey) throw new Error("job signer used an unexpected key");
  }
  return { ...envelope, signature };
}

/** Tests only: forget cached keys/tokens (e.g. after switching REPO_DIR or JOB_SIGNER). */
export function resetJobSigningKeyCache(): void {
  cached = undefined;
  cachedToken = undefined;
  publicKeyCache.clear();
}
