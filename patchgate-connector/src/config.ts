import { readFile } from "node:fs/promises";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { z } from "zod";
import { writeFileAtomic } from "./util/fsx.ts";

/**
 * Connector configuration (JSON file, validated by zod). Secrets are NOT stored here:
 *  - the connector's Ed25519 private key lives in identity.privateKeyFile (mode 0600),
 *  - the Tactical API key is read from tactical.apiKeyFile or env PATCHGATE_TACTICAL_API_KEY.
 * `init` fills `server` + `identity`; everything else is written by the operator.
 */

/** Same shape the PC-side install script accepts for PG_REPO_URL. */
export const CACHE_BASE_URL_RE = /^https:\/\/[A-Za-z0-9.-]+(:[0-9]{1,5})?(\/[A-Za-z0-9._-]+)*$/;
const DEV_CACHE_BASE_URL_RE = /^https?:\/\/[A-Za-z0-9.-]+(:[0-9]{1,5})?(\/[A-Za-z0-9._-]+)*$/;
export const SIEM_URL_RE = /^(tls|tcp):\/\/([A-Za-z0-9.-]+):(\d{1,5})$/;
const ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
const GiB = 1024 ** 3;

const filePath = z.string().min(1).max(1024);
const positiveInt = z.number().int().positive();

export const serverSchema = z.object({
  url: z.url().max(300),
  caFile: filePath.optional(),
  requestTimeoutMs: positiveInt.max(600_000).default(30_000),
  /** Optional cap on package downloads from PatchGate (bank internet uplink). */
  downloadLimitMbps: positiveInt.nullable().default(null),
});

export const identitySchema = z.object({
  connectorId: z.string().regex(ID_RE),
  tenantId: z.string().regex(ID_RE),
  name: z.string().max(200),
  jobSigningPublicKey: z.string().regex(/^[A-Za-z0-9+/]{43}=$/, "base64 Ed25519 public key"),
  privateKeyFile: filePath,
  enrolledAt: z.string(),
});

export const tacticalSchema = z.object({
  url: z.url().max(300),
  apiKeyFile: filePath.optional(),
  caFile: filePath.optional(),
  timeoutMs: positiveInt.max(600_000).default(30_000),
  /** Tactical script id of the signed Install-PatchGatePackage.ps1 (fixed; never taken from a job). */
  installScriptId: positiveInt.optional(),
  installScriptTimeoutSec: positiveInt.max(7200).default(900),
  /** Tactical script id of the signed Invoke-PatchGateWuScan.ps1 (WU_SCAN; offline scan, read-only). */
  wuScanScriptId: positiveInt.optional(),
  /** Tactical script id of the signed Install-PatchGateWinUpdate.ps1 (WU_INSTALL). */
  wuInstallScriptId: positiveInt.optional(),
  /** Offline scans against wsusscn2.cab take minutes (first run also copies ~700 MB from the cache). */
  wuScanTimeoutSec: positiveInt.min(300).max(7200).default(3600),
  wuInstallTimeoutSec: positiveInt.min(300).max(7200).default(3600),
  /** How often the heartbeat refreshes Tactical reachability + agent count. */
  statusIntervalSec: positiveInt.default(300),
  /** Parallel Tactical calls inside one SCAN/COLLECT batch. */
  maxParallelCalls: positiveInt.max(64).default(8),
});

export const cacheSchema = z.object({
  dir: filePath.optional(),
  /** URL PCs use to reach this cache (becomes PG_REPO_URL). Its path is the URL prefix served. */
  baseUrl: z.string().max(300),
  listenHost: z.string().min(1).default("0.0.0.0"),
  port: z.number().int().min(1).max(65535).default(8443),
  tls: z.object({ certFile: filePath, keyFile: filePath }).optional(),
  maxPackageBytes: positiveInt.max(4 * GiB).default(4 * GiB),
  minFreeBytes: z.number().int().min(0).default(GiB),
  /** Total size cap of the cache; least-recently-used packages no unexpired job refers to are evicted. */
  maxCacheBytes: positiveInt.nullable().default(null),
  maxConcurrentDownloads: positiveInt.max(10_000).default(50),
  perClientConcurrency: positiveInt.max(100).default(2),
  /** Local ceiling (Mbit/s) for all cache downloads together; PatchGate may only lower it. */
  bandwidthLimitMbps: positiveInt.nullable().default(null),
  retryAfterSec: positiveInt.max(3600).default(30),
});

export const limitsSchema = z.object({
  /** Local ceiling for concurrent DEPLOY_* jobs; PatchGate's heartbeat value may only lower it. */
  maxConcurrentInstalls: positiveInt.max(1000).default(50),
  maxConcurrentOtherJobs: positiveInt.max(100).default(4),
  maxQueuedJobs: positiveInt.max(10_000).default(200),
  heartbeatIntervalSec: positiveInt.max(3600).default(60),
  pollWaitSec: positiveInt.max(25).default(25),
  shutdownGraceSec: positiveInt.max(3600).default(60),
  journalRetentionDays: positiveInt.max(3650).default(30),
  /** Size cap of journal.jsonl (compacted at runtime; oldest acknowledged stubs evicted beyond it). */
  journalMaxBytes: positiveInt.min(1024 * 1024).max(4 * GiB).default(64 * 1024 * 1024),
});

const APP_ID_RE = /^[A-Za-z0-9][A-Za-z0-9.+_-]{2,127}$/;
/** One exact publisher pin, as the PC-side script compares it with the Authenticode subject O=. */
const PUBLISHER_PIN_RE = /^O=[A-Za-z0-9 .,&()'+-]{2,200}$/;

/**
 * OPTIONAL bank-held trust policy (defence in depth vs. a compromised PatchGate platform).
 * See README "Local trust policy".
 */
export const trustSchema = z
  .object({
    /** wingetId → exact "O=..." pins. If set, msi/exe packages must match (the job may only narrow). */
    publishers: z.record(z.string().regex(APP_ID_RE, "wingetId"), z.array(z.string().regex(PUBLISHER_PIN_RE, 'publisher pin must be "O=<organisation>"')).min(1).max(8)).optional(),
    /** With publishers set: allow msi/exe apps that are not listed (default false = refuse). */
    allowUnlistedApps: z.boolean().default(false),
    /** Allow-list of Tactical agent build SHA-256s (kind "agent" is unsigned). If set, others are refused. */
    agentSha256: z.array(z.string().regex(/^[a-f0-9]{64}$/, "lowercase hex SHA-256")).min(1).max(200).optional(),
  })
  .strict();

export const siemSchema = z.object({
  url: z.string().regex(SIEM_URL_RE, "SIEM URL must look like tls://host:port"),
  caFile: filePath.optional(),
  /** HOSTNAME field of the RFC 5424 records (default: os hostname). */
  hostname: z.string().max(255).optional(),
  pollIntervalSec: positiveInt.max(3600).default(30),
  batchSize: positiveInt.max(500).default(500),
});

export const configSchema = z
  .object({
    stateDir: filePath,
    logLevel: z.enum(["debug", "info", "warn", "error"]).default("info"),
    /** Allows http:// PatchGate / cache URLs and tcp:// SIEM. Lab/dev only — never in a bank. */
    insecureDev: z.boolean().default(false),
    server: serverSchema.optional(),
    identity: identitySchema.optional(),
    tactical: tacticalSchema,
    cache: cacheSchema,
    limits: limitsSchema.prefault({}),
    siem: siemSchema.optional(),
    trust: trustSchema.optional(),
  })
  .strict()
  .superRefine((c, ctx) => {
    if (c.server && !c.insecureDev && !c.server.url.startsWith("https://")) {
      ctx.addIssue({ code: "custom", path: ["server", "url"], message: "PatchGate URL must be https:// (http only with insecureDev)" });
    }
    const baseRe = c.insecureDev ? DEV_CACHE_BASE_URL_RE : CACHE_BASE_URL_RE;
    if (!baseRe.test(c.cache.baseUrl)) {
      ctx.addIssue({ code: "custom", path: ["cache", "baseUrl"], message: "cache.baseUrl must look like https://host[:port][/path] (no trailing slash)" });
    }
    if (!c.cache.tls && !c.insecureDev) {
      ctx.addIssue({ code: "custom", path: ["cache", "tls"], message: "cache.tls (certFile, keyFile) is required" });
    }
    if (c.siem && c.siem.url.startsWith("tcp://") && !c.insecureDev) {
      ctx.addIssue({ code: "custom", path: ["siem", "url"], message: "SIEM must use tls:// (tcp only with insecureDev)" });
    }
    if (!c.insecureDev && !c.tactical.url.startsWith("https://")) {
      ctx.addIssue({ code: "custom", path: ["tactical", "url"], message: "Tactical URL must be https:// (http only with insecureDev)" });
    }
  });

export type ConnectorConfig = z.infer<typeof configSchema>;
export type ConfigInput = z.input<typeof configSchema>;

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}

function formatIssues(err: z.ZodError): string {
  return err.issues.map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`).join("; ");
}

/** Parse + validate; relative file paths are resolved against the config file's directory. */
export function parseConfig(raw: unknown, baseDir: string): ConnectorConfig {
  const parsed = configSchema.safeParse(raw);
  if (!parsed.success) throw new ConfigError(`invalid config: ${formatIssues(parsed.error)}`);
  const c = parsed.data;
  const abs = (p: string): string => (isAbsolute(p) ? p : resolve(baseDir, p));
  const absOpt = (p: string | undefined): string | undefined => (p === undefined ? undefined : abs(p));
  const stateDir = abs(c.stateDir);
  return {
    ...c,
    stateDir,
    server: c.server ? { ...c.server, caFile: absOpt(c.server.caFile) } : undefined,
    identity: c.identity ? { ...c.identity, privateKeyFile: abs(c.identity.privateKeyFile) } : undefined,
    tactical: { ...c.tactical, apiKeyFile: absOpt(c.tactical.apiKeyFile), caFile: absOpt(c.tactical.caFile) },
    cache: {
      ...c.cache,
      dir: c.cache.dir ? abs(c.cache.dir) : join(stateDir, "cache"),
      tls: c.cache.tls ? { certFile: abs(c.cache.tls.certFile), keyFile: abs(c.cache.tls.keyFile) } : undefined,
    },
    siem: c.siem ? { ...c.siem, caFile: absOpt(c.siem.caFile) } : undefined,
  };
}

export async function readRawConfig(path: string): Promise<Record<string, unknown>> {
  let text: string;
  try {
    text = await readFile(path, "utf8");
  } catch (err) {
    throw new ConfigError(`cannot read config ${path}: ${(err as NodeJS.ErrnoException).code ?? "error"}`);
  }
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    throw new ConfigError(`config ${path} is not valid JSON`);
  }
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) throw new ConfigError(`config ${path} must be a JSON object`);
  return raw as Record<string, unknown>;
}

export async function loadConfig(path: string): Promise<ConnectorConfig> {
  return parseConfig(await readRawConfig(path), dirname(resolve(path)));
}

/** Validate then atomically write the raw (unresolved) config back (mode 0600). */
export async function saveRawConfig(path: string, raw: Record<string, unknown>): Promise<ConnectorConfig> {
  const cfg = parseConfig(raw, dirname(resolve(path)));
  await writeFileAtomic(path, `${JSON.stringify(raw, null, 2)}\n`, 0o600);
  return cfg;
}

export type EnrolledConfig = ConnectorConfig & {
  server: NonNullable<ConnectorConfig["server"]>;
  identity: NonNullable<ConnectorConfig["identity"]>;
};

export function requireEnrolled(c: ConnectorConfig): EnrolledConfig {
  if (!c.server || !c.identity) throw new ConfigError("connector is not enrolled yet: run `patchgate-connector init` first");
  return c as EnrolledConfig;
}

/** Tactical API key from apiKeyFile, else env PATCHGATE_TACTICAL_API_KEY. */
export async function loadTacticalApiKey(c: ConnectorConfig, env: NodeJS.ProcessEnv = process.env): Promise<string> {
  let key: string | undefined;
  if (c.tactical.apiKeyFile) {
    try {
      key = (await readFile(c.tactical.apiKeyFile, "utf8")).trim();
    } catch (err) {
      throw new ConfigError(`cannot read tactical.apiKeyFile: ${(err as NodeJS.ErrnoException).code ?? "error"}`);
    }
  } else {
    key = env.PATCHGATE_TACTICAL_API_KEY?.trim();
  }
  if (!key) throw new ConfigError("Tactical API key missing: set tactical.apiKeyFile or PATCHGATE_TACTICAL_API_KEY");
  if (!/^[\x21-\x7e]{8,256}$/.test(key)) throw new ConfigError("Tactical API key has an invalid format");
  return key;
}

/** URL path prefix served by the cache server, from cache.baseUrl (e.g. "/repo" or ""). */
export function cachePathPrefix(baseUrl: string): string {
  const p = new URL(baseUrl).pathname.replace(/\/+$/, "");
  return p === "/" ? "" : p;
}
