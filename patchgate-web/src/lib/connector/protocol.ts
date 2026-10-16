/**
 * PatchGate ⇄ Connector protocol v1 — the SINGLE source of truth, shared verbatim by
 * patchgate-web (server side) and patchgate-connector (bank side; copied, checked identical in CI).
 * Dependencies: node:crypto + zod only. No framework imports.
 *
 * Direction: the connector (inside the bank) ALWAYS initiates (outbound HTTPS). Nothing connects into a bank.
 *
 * 1. Request authentication (every call except enroll):
 *      headers  x-pg-connector  connector id
 *               x-pg-timestamp  unix ms
 *               x-pg-nonce      16 random bytes, base64url (single use)
 *               x-pg-signature  base64 Ed25519(connector private key, canonicalRequest)
 *      canonicalRequest = "PGC1\n" + METHOD + "\n" + pathWithQuery + "\n" + timestamp + "\n" + nonce + "\n" + sha256hex(body)
 *      Server rejects: unknown/revoked connector, |now - timestamp| > 5 min, reused nonce, bad signature.
 * 2. Enrolment: POST /api/connector/v1/enroll { code, publicKey, name?, version, proof }
 *      proof = base64 Ed25519(private key, "PGC1-ENROLL\n" + code + "\n" + publicKey)  (proof of possession)
 *      → { connectorId, tenantId, jobSigningPublicKey }   (connector pins jobSigningPublicKey)
 * 3. Jobs: GET /api/connector/v1/jobs?wait=25 → { jobs: SignedJob[] } (long poll, ≤ 25 s, ≤ 20 jobs)
 *      Every job is signed by PatchGate's job-signing key over canonicalJson(envelope). The connector
 *      verifies signature, connectorId == self, now < expiresAt, now ≥ notBefore, and the typed payload.
 *    POST /api/connector/v1/jobs/{id}/result  JobResult  (idempotent: first accepted result wins)
 * 4. Packages: GET /api/connector/v1/packages/{sha256} → bytes; connector re-hashes before caching.
 * 5. Audit relay: GET /api/connector/v1/audit?after={seq}&limit=500 → this bank's chain records (each with prevHash) + head.
 * 6. Heartbeat: POST /api/connector/v1/heartbeat { version, cacheBaseUrl, cache: {...}, tactical: {...} }
 */
import { createHash, createPrivateKey, createPublicKey, sign, verify, type KeyObject } from "node:crypto";
import { z } from "zod";

export const PROTOCOL_VERSION = 1;
export const API_PREFIX = "/api/connector/v1";
export const MAX_CLOCK_SKEW_MS = 5 * 60_000;
export const MAX_JOBS_PER_POLL = 20;
/** A signed job may never be valid for longer than this (limits the value of a stolen/replayed job). */
export const MAX_JOB_LIFETIME_MS = 72 * 3_600_000;
export const MAX_AGENTS_PER_JOB = 200;
export const HEADERS = {
  connector: "x-pg-connector",
  timestamp: "x-pg-timestamp",
  nonce: "x-pg-nonce",
  signature: "x-pg-signature",
} as const;

// ---------------------------------------------------------------------------------------------
// Keys (Ed25519; public keys travel as base64 of the raw 32 bytes)
// ---------------------------------------------------------------------------------------------

const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export function publicKeyFromRaw(rawB64: string): KeyObject {
  const raw = Buffer.from(rawB64, "base64");
  if (raw.length !== 32) throw new Error("Ed25519 public key must be 32 bytes");
  return createPublicKey({ key: Buffer.concat([SPKI_ED25519_PREFIX, raw]), format: "der", type: "spki" });
}

export function rawFromPublicKey(key: KeyObject): string {
  const der = key.export({ format: "der", type: "spki" });
  return Buffer.from(der.subarray(der.length - 32)).toString("base64");
}

export function privateKeyFromPem(pem: string): KeyObject {
  const k = createPrivateKey(pem);
  if (k.asymmetricKeyType !== "ed25519") throw new Error("expected an Ed25519 private key");
  return k;
}

export const sha256Hex = (data: string | Uint8Array) => createHash("sha256").update(data).digest("hex");

// ---------------------------------------------------------------------------------------------
// Canonical JSON (sorted keys, no whitespace) — what job signatures cover
// ---------------------------------------------------------------------------------------------

export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    if (typeof value === "number" && !Number.isFinite(value)) throw new Error("non-finite number");
    if (value === undefined) throw new Error("undefined is not allowed");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(",")}}`;
}

// ---------------------------------------------------------------------------------------------
// Request signing
// ---------------------------------------------------------------------------------------------

export function canonicalRequest(method: string, pathWithQuery: string, timestamp: string, nonce: string, body: string | Uint8Array): string {
  return ["PGC1", method.toUpperCase(), pathWithQuery, timestamp, nonce, sha256Hex(body)].join("\n");
}

export function signRequest(privateKey: KeyObject, method: string, pathWithQuery: string, timestamp: string, nonce: string, body: string | Uint8Array): string {
  return sign(null, Buffer.from(canonicalRequest(method, pathWithQuery, timestamp, nonce, body)), privateKey).toString("base64");
}

export function verifyRequest(
  publicKeyRawB64: string,
  sig: string,
  method: string,
  pathWithQuery: string,
  timestamp: string,
  nonce: string,
  body: string | Uint8Array,
): boolean {
  try {
    return verify(null, Buffer.from(canonicalRequest(method, pathWithQuery, timestamp, nonce, body)), publicKeyFromRaw(publicKeyRawB64), Buffer.from(sig, "base64"));
  } catch {
    return false;
  }
}

/** Timestamp must be within ±5 min of the server clock. */
export function timestampFresh(timestamp: string, nowMs: number): boolean {
  if (!/^\d{12,14}$/.test(timestamp)) return false;
  return Math.abs(nowMs - Number(timestamp)) <= MAX_CLOCK_SKEW_MS;
}

export const NONCE_RE = /^[A-Za-z0-9_-]{16,64}$/;

// ---------------------------------------------------------------------------------------------
// Enrolment
// ---------------------------------------------------------------------------------------------

export const ENROLL_CODE_RE = /^[A-Z0-9]{4}(-[A-Z0-9]{4}){4}$/; // e.g. 7Q2M-K9XD-4HPA-ZT3W-8NBC (100 bits)

export function enrollProofMessage(code: string, publicKeyRawB64: string): string {
  return `PGC1-ENROLL\n${code}\n${publicKeyRawB64}`;
}

export const enrollRequestSchema = z.object({
  code: z.string().regex(ENROLL_CODE_RE),
  publicKey: z.string().regex(/^[A-Za-z0-9+/]{43}=$/, "base64 Ed25519 public key"),
  version: z.string().regex(/^[0-9A-Za-z.+_-]{1,40}$/),
  proof: z.string().max(200),
});
export type EnrollRequest = z.infer<typeof enrollRequestSchema>;

export const enrollResponseSchema = z.object({
  connectorId: z.string().min(1).max(64),
  tenantId: z.string().min(1).max(64),
  name: z.string(),
  jobSigningPublicKey: z.string(),
});

// ---------------------------------------------------------------------------------------------
// Job payloads (typed — the connector never executes arbitrary Tactical calls)
// ---------------------------------------------------------------------------------------------

const agentId = z.string().regex(/^[A-Za-z0-9_-]{6,64}$/, "invalid Tactical agent id");
const agentIds = z.array(agentId).min(1).max(MAX_AGENTS_PER_JOB);
const updateGuid = z.string().regex(/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/);
const sha256 = z.string().regex(/^[a-f0-9]{64}$/);
const repoPath = z
  .string()
  .max(256)
  .regex(/^(pkgs|tactical|winupdate)\/[A-Za-z0-9._-]+(\/[A-Za-z0-9._-]+)*$/)
  .refine((p) => !p.split("/").some((s) => s === "." || s === ".."), "path traversal");

/**
 * Package as the PC-side scripts consume it (PatchGate validates fully before signing).
 * msi/exe/agent: third-party + Tactical agent installs. msu/cab: Microsoft update files.
 * wsusscan: Microsoft's signed offline scan catalog (wsusscn2.cab) used by WU_SCAN.
 */
export const jobPackageSchema = z.object({
  kind: z.enum(["msi", "exe", "agent", "msu", "cab", "wsusscan"]),
  wingetId: z.string().max(128),
  version: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}$/),
  sha256,
  size: z.number().int().positive().max(4 * 1024 ** 3),
  repoPath,
  publisher: z.string().max(1000),
  switches: z.string().max(200),
});
export type JobPackage = z.infer<typeof jobPackageSchema>;

export const jobPayloadSchemas = {
  /** List all Tactical agents at this site. */
  SYNC_AGENTS: z.object({}).strict(),
  /** Ask agents to rescan Windows Update. */
  SCAN: z.object({ agentIds }).strict(),
  /** Read updates / software / agent version for a batch of agents. */
  COLLECT: z.object({ agentIds, updates: z.boolean(), software: z.boolean(), agent: z.boolean() }).strict(),
  /** Approve exactly these update GUIDs (everything else not approved) and start installation. */
  DEPLOY_WINDOWS: z.object({ agentId, guids: z.array(updateGuid).min(1).max(500), rebootPolicy: z.enum(["NEVER", "IF_REQUIRED", "FORCE"]) }).strict(),
  /** Run the fixed, signed PatchGate install script for one package on one agent (package must be cached). */
  DEPLOY_PACKAGE: z.object({ agentId, package: jobPackageSchema }).strict(),
  /** Return an agent's update approvals to "not approved" (rollback / cancel). */
  RESET_APPROVALS: z.object({ agentId }).strict(),
  /** Download a package from PatchGate into the site cache (once per site). */
  CACHE_PACKAGE: z.object({ package: jobPackageSchema }).strict(),
  /**
   * Windows updates WITHOUT WSUS/internet: each agent scans offline against Microsoft's signed scan
   * catalog (wsusscn2.cab, kind "wsusscan", must be cached) and reports applicable updates + their files.
   */
  WU_SCAN: z.object({ agentIds, scanCab: jobPackageSchema }).strict(),
  /** Install approved Microsoft update files (kind msu/cab, all cached + hash re-checked) on one agent. */
  WU_INSTALL: z
    .object({
      agentId,
      updates: z.array(z.object({ updateId: updateGuid, kb: z.string().regex(/^KB\d{4,8}$/).nullable(), files: z.array(jobPackageSchema).min(1).max(20) })).min(1).max(100),
      rebootPolicy: z.enum(["NEVER", "IF_REQUIRED", "FORCE"]),
    })
    .strict(),
} as const;

export type JobType = keyof typeof jobPayloadSchemas;
export const JOB_TYPES = Object.keys(jobPayloadSchemas) as JobType[];
export type JobPayload<T extends JobType> = z.infer<(typeof jobPayloadSchemas)[T]>;

export interface JobEnvelope {
  v: 1;
  id: string;
  tenantId: string;
  connectorId: string;
  type: JobType;
  payload: unknown;
  notBefore: string; // ISO
  expiresAt: string; // ISO
}

export interface SignedJob extends JobEnvelope {
  signature: string;
}

export function signJob(jobKey: KeyObject, env: JobEnvelope): SignedJob {
  const signature = sign(null, Buffer.from(canonicalJson(env)), jobKey).toString("base64");
  return { ...env, signature };
}

export type JobCheck = { ok: true; type: JobType; payload: unknown } | { ok: false; reason: string };

/** Everything the connector checks before touching Tactical. */
export function verifyJob(job: SignedJob, jobSigningPublicKeyRaw: string, selfConnectorId: string, nowMs: number): JobCheck {
  const { signature, ...env } = job;
  if (env.v !== 1) return { ok: false, reason: "unsupported job version" };
  let sigOk = false;
  try {
    sigOk = verify(null, Buffer.from(canonicalJson(env)), publicKeyFromRaw(jobSigningPublicKeyRaw), Buffer.from(signature ?? "", "base64"));
  } catch {
    sigOk = false;
  }
  if (!sigOk) return { ok: false, reason: "bad job signature" };
  if (env.connectorId !== selfConnectorId) return { ok: false, reason: "job is for another connector" };
  if (!(env.type in jobPayloadSchemas)) return { ok: false, reason: "unknown job type" };
  const expires = Date.parse(env.expiresAt);
  if (!Number.isFinite(expires) || nowMs >= expires) return { ok: false, reason: "job expired" };
  const nb = Date.parse(env.notBefore);
  if (!Number.isFinite(nb) || nowMs + MAX_CLOCK_SKEW_MS < nb) return { ok: false, reason: "job not yet valid" };
  if (expires - nb > MAX_JOB_LIFETIME_MS) return { ok: false, reason: "job lifetime too long" };
  const parsed = jobPayloadSchemas[env.type].safeParse(env.payload);
  if (!parsed.success) return { ok: false, reason: `invalid payload: ${parsed.error.issues[0]?.message ?? "?"}` };
  return { ok: true, type: env.type, payload: parsed.data };
}

// ---------------------------------------------------------------------------------------------
// Results (connector → PatchGate)
// ---------------------------------------------------------------------------------------------

const shortText = z.string().max(2000);

export const agentInfoSchema = z.object({
  agentId,
  hostname: z.string().max(255),
  site: z.string().max(255).nullish(),
  client: z.string().max(255).nullish(),
  os: z.string().max(255).nullish(),
  goarch: z.string().max(16).nullish(),
  version: z.string().max(40).nullish(),
  online: z.boolean().nullish(),
});

export const winUpdateResultSchema = z.object({
  id: z.number().int(),
  guid: z.string().max(64),
  kb: z.string().max(64).nullable(),
  title: z.string().max(1000).nullable(),
  installed: z.boolean(),
  action: z.string().max(16),
  severity: z.string().max(32).nullable(),
});

export const softwareResultSchema = z.object({
  name: z.string().max(300),
  version: z.string().max(100).default(""),
  publisher: z.string().max(300).nullish(),
  uninstall: z.string().max(2000).nullish(),
});

export const resultSchemas = {
  SYNC_AGENTS: z.object({ agents: z.array(agentInfoSchema).max(10_000) }),
  SCAN: z.object({ requested: z.array(agentId), failed: z.array(z.object({ agentId, error: shortText })) }),
  COLLECT: z.object({
    agents: z
      .array(
        z.object({
          agentId,
          updates: z.array(winUpdateResultSchema).max(2000).optional(),
          software: z.array(softwareResultSchema).max(3000).optional(),
          agent: z.object({ version: z.string().max(40), goarch: z.string().max(16).nullish() }).optional(),
          error: shortText.optional(),
        }),
      )
      .max(MAX_AGENTS_PER_JOB),
  }),
  DEPLOY_WINDOWS: z.object({ outcome: z.enum(["INSTALL_STARTED", "NOTHING_TO_DO"]), approved: z.array(z.string()).max(500) }),
  DEPLOY_PACKAGE: z.object({ outcome: z.enum(["INSTALLED", "ALREADY_INSTALLED"]), output: shortText.optional() }),
  RESET_APPROVALS: z.object({ reset: z.number().int().min(0) }),
  CACHE_PACKAGE: z.object({ sha256, size: z.number().int().positive(), cachedPath: z.string().max(512) }),
  WU_SCAN: z.object({
    agents: z
      .array(
        z.object({
          agentId,
          updates: z
            .array(
              z.object({
                updateId: updateGuid,
                revision: z.number().int().min(0),
                kb: z.string().max(16).nullable(),
                title: z.string().max(1000),
                msrcSeverity: z.string().max(32).nullable(),
                classification: z.string().max(100).nullable(),
                // Microsoft download locations reported by the offline scan (PatchGate fetches them, never the PC)
                files: z
                  .array(z.object({ url: z.string().url().max(2048), name: z.string().max(260), size: z.number().int().min(0), sha1: z.string().max(64).nullable(), sha256: z.string().max(64).nullable() }))
                  .max(20),
              }),
            )
            .max(1000)
            .optional(),
          error: shortText.optional(),
        }),
      )
      .max(MAX_AGENTS_PER_JOB),
  }),
  WU_INSTALL: z.object({
    outcome: z.enum(["INSTALLED", "PARTIAL", "NOTHING_TO_DO"]),
    installed: z.array(z.string()).max(100),
    failed: z.array(z.object({ updateId: z.string(), error: shortText })).max(100),
    rebootRequired: z.boolean(),
  }),
} as const;

export const jobResultSchema = z.discriminatedUnion("ok", [
  z.object({ ok: z.literal(true), result: z.unknown() }),
  // retryable=true: transient (agent offline, Tactical busy) — PatchGate may re-queue.
  // outcomeUnknown=true: an install MAY have run (timeout / connection lost while the script was running).
  // Never retried blindly (no double installers): PatchGate confirms via inventory instead of failing.
  z.object({ ok: z.literal(false), error: shortText, retryable: z.boolean(), outcomeUnknown: z.boolean().optional() }),
]);
export type JobResult = z.infer<typeof jobResultSchema>;

// ---------------------------------------------------------------------------------------------
// Heartbeat + audit relay
// ---------------------------------------------------------------------------------------------

export const heartbeatSchema = z.object({
  version: z.string().max(40),
  cacheBaseUrl: z.url().max(300).nullish(),
  cache: z.object({ files: z.number().int().min(0), bytes: z.number().int().min(0), freeBytes: z.number().int().min(0).nullish() }),
  tactical: z.object({ reachable: z.boolean(), agents: z.number().int().min(0).nullish(), error: shortText.nullish() }),
  siem: z.object({ configured: z.boolean(), lastForwardedSeq: z.string().max(24).nullish(), error: shortText.nullish() }).optional(),
});
export type Heartbeat = z.infer<typeof heartbeatSchema>;

export const heartbeatResponseSchema = z.object({
  serverTime: z.string(),
  maxConcurrentInstalls: z.number().int().positive(),
  bandwidthLimitMbps: z.number().int().positive().nullable(),
});

export const auditRelayResponseSchema = z.object({
  records: z.array(
    z.object({
      seq: z.string(),
      ts: z.string(),
      actor: z.string(),
      action: z.string(),
      entity: z.string(),
      entityId: z.string(),
      hash: z.string(),
      // Hash of the previous record of the same bank chain (SIEM chain-break rule). Optional: older servers omit it.
      prevHash: z.string().nullish(),
      payload: z.unknown(),
    }),
  ),
  head: z.object({ seq: z.string(), hash: z.string() }).nullable(),
});
