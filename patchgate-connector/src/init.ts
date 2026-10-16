import { readFile, rm, access } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { ConfigError, parseConfig, readRawConfig, saveRawConfig, type EnrolledConfig, requireEnrolled } from "./config.ts";
import { generateConnectorKey, savePrivateKey } from "./keys.ts";
import { enroll } from "./pg-client.ts";
import { ENROLL_CODE_RE, publicKeyFromRaw, sha256Hex } from "./protocol.ts";
import type { Logger } from "./util/log.ts";

/**
 * `init`: generate the connector's Ed25519 key locally, enrol with a one-time code (proof of
 * possession), pin PatchGate's job-signing public key, and store the identity in the config.
 */

export interface InitOptions {
  configPath: string;
  serverUrl: string;
  code: string;
  caFile?: string;
  /**
   * SHA-256 (hex) of PatchGate's raw 32-byte job-signing public key, obtained out of band from the
   * PatchGate operator. Required unless insecureDev: the key is otherwise trusted on first use.
   */
  jobKeyFingerprint?: string;
  insecureDev: boolean;
  force: boolean;
  version: string;
  log: Logger;
}

export function validateServerUrl(raw: string, insecureDev: boolean): string {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new ConfigError("--server is not a valid URL");
  }
  if (u.username || u.password) throw new ConfigError("--server must not contain credentials");
  if (u.protocol === "http:" && !insecureDev) throw new ConfigError("refusing http:// PatchGate URL (use https://, or --insecure-dev in a lab)");
  if (u.protocol !== "https:" && u.protocol !== "http:") throw new ConfigError("--server must be https://");
  return u.origin;
}

/** Normalise a fingerprint as operators paste it: hex, optional "sha256:" prefix, colons/spaces allowed. */
export function normalizeFingerprint(raw: string): string {
  const hex = raw.trim().toLowerCase().replace(/^sha256:/, "").replace(/[: ]/g, "");
  if (!/^[a-f0-9]{64}$/.test(hex)) throw new ConfigError("--job-key-fingerprint must be the 64-hex-digit SHA-256 of the raw 32-byte job-signing public key");
  return hex;
}

/** Fingerprint of a job-signing public key (base64 of the raw 32 bytes): lowercase hex SHA-256 of the raw bytes. */
export function jobKeyFingerprint(publicKeyRawB64: string): string {
  return sha256Hex(Buffer.from(publicKeyRawB64, "base64"));
}

async function exists(p: string): Promise<boolean> {
  try {
    await access(p);
    return true;
  } catch {
    return false;
  }
}

export async function runInit(o: InitOptions): Promise<EnrolledConfig> {
  const code = o.code.trim().toUpperCase();
  if (!ENROLL_CODE_RE.test(code)) throw new ConfigError("enrolment code must look like XXXX-XXXX-XXXX-XXXX-XXXX");
  const serverUrl = validateServerUrl(o.serverUrl, o.insecureDev);
  // The job-signing key is pinned at enrolment: without an out-of-band fingerprint a malicious or
  // intercepted enrolment endpoint could pin its own key (trust on first use). Lab only otherwise.
  const expectedFp = o.jobKeyFingerprint === undefined ? undefined : normalizeFingerprint(o.jobKeyFingerprint);
  if (!expectedFp && !o.insecureDev) throw new ConfigError("init needs --job-key-fingerprint <sha256 hex of PatchGate's job-signing public key> (get it from the PatchGate operator out of band)");

  const configPath = resolve(o.configPath);
  const raw = await readRawConfig(configPath);
  const current = parseConfig(raw, dirname(configPath)); // validates operator-provided sections first
  if (current.identity && !o.force) throw new ConfigError("connector is already enrolled (use --force to re-enrol with a new key)");

  const caFile = o.caFile ? resolve(o.caFile) : undefined;
  const ca = caFile ? await readFile(caFile) : undefined;
  const keyFile = current.identity?.privateKeyFile ?? join(current.stateDir, "connector-key.pem");
  if ((await exists(keyFile)) && !o.force) throw new ConfigError(`key file already exists: ${keyFile} (use --force)`);

  // The new key is written next to the old one first; it replaces the active key only after the
  // server accepted it, so a failed re-enrolment never destroys a working identity.
  const key = generateConnectorKey();
  const pendingFile = `${keyFile}.pending`;
  await savePrivateKey(pendingFile, key.privatePem);
  try {
    const res = await enroll({
      serverUrl,
      ca,
      code,
      publicKey: key.publicKey,
      privateKey: key.privateKey,
      version: o.version,
      timeoutMs: 30_000,
    });
    publicKeyFromRaw(res.jobSigningPublicKey); // must be a valid Ed25519 key before we pin it
    const actualFp = jobKeyFingerprint(res.jobSigningPublicKey);
    if (expectedFp && actualFp !== expectedFp) {
      o.log.error("job-signing key fingerprint MISMATCH; enrolment not saved", { security: true, expected: expectedFp, received: actualFp, server: serverUrl });
      throw new ConfigError(`job-signing key fingerprint mismatch: PatchGate sent ${actualFp}, expected ${expectedFp}. Nothing was saved; check the server URL / CA and contact the PatchGate operator.`);
    }
    if (!expectedFp) o.log.warn("job-signing key pinned WITHOUT fingerprint check (--insecure-dev)", { security: true, fingerprint: actualFp });
    await savePrivateKey(keyFile, key.privatePem);
    await rm(pendingFile, { force: true });
    const next: Record<string, unknown> = {
      ...raw,
      insecureDev: o.insecureDev || raw.insecureDev === true,
      server: { ...(typeof raw.server === "object" && raw.server ? raw.server : {}), url: serverUrl, ...(caFile ? { caFile } : {}) },
      identity: {
        connectorId: res.connectorId,
        tenantId: res.tenantId,
        name: res.name.slice(0, 200),
        jobSigningPublicKey: res.jobSigningPublicKey,
        privateKeyFile: keyFile,
        enrolledAt: new Date().toISOString(),
      },
    };
    const saved = await saveRawConfig(configPath, next);
    o.log.info("enrolled", { connectorId: res.connectorId, tenantId: res.tenantId, name: res.name, server: serverUrl, jobKeyFingerprint: actualFp });
    return requireEnrolled(saved);
  } catch (err) {
    await rm(pendingFile, { force: true }); // never registered: do not leave it behind
    throw err;
  }
}
