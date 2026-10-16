import { generateKeyPairSync } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { JOB_TYPES, MAX_JOB_LIFETIME_MS, canonicalJson, verifyJob, type JobEnvelope } from "./protocol";

// The signer service (deploy/signer/server.mjs) is outside this package (and outside the Docker build
// context), so it is loaded dynamically; the remote-mode tests are skipped when it is not present.
const SIGNER_PATH = fileURLToPath(new URL("../../../../deploy/signer/server.mjs", import.meta.url));
const HAS_SIGNER = existsSync(SIGNER_PATH);

interface SignerServer extends Server {
  reloadKeys(): void;
}
interface SignerModule {
  createSigner(opts: { token: string; keyDir: string; audit?: (line: string) => void; now?: () => number }): SignerServer;
  JOB_TYPES: readonly string[];
  MAX_JOB_LIFETIME_MS: number;
  canonicalJson(v: unknown): string;
}

const TOKEN = "s".repeat(48);
const BASE_ENV: Record<string, string> = {
  NODE_ENV: "test",
  DATABASE_URL: "postgresql://u:p@localhost:5432/db",
  TACTICAL_API_URL: "https://tactical.invalid",
  TACTICAL_API_KEY: "x".repeat(32),
  PATCH_REPO_URL: "https://repo.invalid/repo",
  AUDIT_HMAC_KEY: "a".repeat(64),
  WORKER_TOKEN: "w".repeat(64),
  AUTH_ENC_KEY: "0".repeat(64),
};

const tmp = mkdtempSync(join(tmpdir(), "pg-keys-test-"));
const pem = () => generateKeyPairSync("ed25519").privateKey.export({ format: "pem", type: "pkcs8" }).toString();

async function loadKeys(extra: Record<string, string | undefined>) {
  vi.resetModules();
  vi.unstubAllEnvs();
  for (const [k, v] of Object.entries({ ...BASE_ENV, ...extra })) vi.stubEnv(k, v);
  return import("./keys");
}

function envelope(over: Partial<JobEnvelope> = {}): JobEnvelope {
  const now = Date.now();
  return {
    v: 1,
    id: "job_AAAAAAAAAAAAAAAAAAAA",
    tenantId: "tenantA",
    connectorId: "conn1",
    type: "SYNC_AGENTS",
    payload: {},
    notBefore: new Date(now - 1000).toISOString(),
    expiresAt: new Date(now + 3_600_000).toISOString(),
    ...over,
  };
}

afterEach(() => {
  vi.unstubAllEnvs();
});
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

describe("JOB_SIGNER=file", () => {
  it("loads JOB_SIGNING_KEY_FILE; one key for all banks; signatures verify", async () => {
    const file = join(tmp, "file-mode.pem");
    writeFileSync(file, pem());
    const keys = await loadKeys({ JOB_SIGNER: "file", JOB_SIGNING_KEY_FILE: file });
    const k = keys.jobSigningKey();
    expect(k.publicKeyRaw).toMatch(/^[A-Za-z0-9+/]{43}=$/);
    expect(keys.jobSigningKey("tenantA").publicKeyRaw).toBe(k.publicKeyRaw);
    expect(await keys.jobSigningPublicKey("tenantA")).toBe(k.publicKeyRaw);
    expect(await keys.jobSigningPublicKey("tenantB")).toBe(k.publicKeyRaw);
    const signed = await keys.signJobEnvelope(envelope());
    expect(verifyJob(signed, k.publicKeyRaw, "conn1", Date.now())).toMatchObject({ ok: true });
    expect(keys.jobKeyFingerprint(k.publicKeyRaw)).toMatch(/^[a-f0-9]{64}$/);
  });

  it("creates a development key under REPO_DIR when no file is configured (non-production)", async () => {
    const keys = await loadKeys({ JOB_SIGNER: "file", REPO_DIR: join(tmp, "repo") });
    const k = keys.jobSigningKey();
    expect(k.file).toContain(".keys");
    expect(existsSync(k.file)).toBe(true);
  });

  it("rejects an invalid tenant id", async () => {
    const file = join(tmp, "file-mode2.pem");
    writeFileSync(file, pem());
    const keys = await loadKeys({ JOB_SIGNING_KEY_FILE: file });
    await expect(keys.jobSigningPublicKey("../x")).rejects.toThrow(/invalid tenant id/);
    await expect(keys.signJobEnvelope(envelope({ tenantId: "a b" }))).rejects.toThrow(/invalid tenant id/);
  });
});

describe("JOB_SIGNER=disabled", () => {
  it("never signs and never exposes a key", async () => {
    const keys = await loadKeys({ JOB_SIGNER: "disabled" });
    expect(() => keys.jobSigningKey()).toThrow(/not available/);
    await expect(keys.signJobEnvelope(envelope())).rejects.toThrow(/disabled/);
    await expect(keys.jobSigningPublicKey("tenantA")).rejects.toThrow(/disabled/);
  });
});

describe("env validation for JOB_SIGNER", () => {
  it("remote requires URL + token file; production file mode requires the key file", async () => {
    vi.resetModules();
    for (const [k, v] of Object.entries({ ...BASE_ENV, JOB_SIGNER: "remote" })) vi.stubEnv(k, v);
    const { env } = await import("@/lib/env");
    expect(() => env()).toThrow(/JOB_SIGNER_URL.*JOB_SIGNER_TOKEN_FILE|JOB_SIGNER_TOKEN_FILE.*JOB_SIGNER_URL/);
  });
});

describe.skipIf(!HAS_SIGNER)("JOB_SIGNER=remote (local signer service)", () => {
  let signerMod: SignerModule;
  let server: SignerServer;
  let url: string;
  const tokenFile = join(tmp, "token");
  const keyDir = join(tmp, "job-keys");
  const audit: string[] = [];

  beforeAll(async () => {
    signerMod = (await import(/* @vite-ignore */ pathToFileURL(SIGNER_PATH).href)) as SignerModule;
    writeFileSync(tokenFile, `${TOKEN}\n`);
    rmSync(keyDir, { recursive: true, force: true });
    mkdirSync(keyDir);
    writeFileSync(join(keyDir, "default.pem"), pem());
    writeFileSync(join(keyDir, "tenantA.pem"), pem());
    server = signerMod.createSigner({ token: TOKEN, keyDir, audit: (l) => audit.push(l) });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
    url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });
  afterAll(() => {
    server?.close();
  });

  it("stays in sync with protocol.ts (job types, lifetime, canonical JSON)", () => {
    expect([...signerMod.JOB_TYPES].sort()).toEqual([...JOB_TYPES].sort());
    expect(signerMod.MAX_JOB_LIFETIME_MS).toBe(MAX_JOB_LIFETIME_MS);
    const sample = { z: [1, { b: true, a: null }], a: "x", u: undefined };
    expect(signerMod.canonicalJson(sample)).toBe(canonicalJson(sample));
  });

  it("signs with the bank's own key, verifiable with the key returned for enrolment", async () => {
    const keys = await loadKeys({ JOB_SIGNER: "remote", JOB_SIGNER_URL: url, JOB_SIGNER_TOKEN_FILE: tokenFile });
    const pubA = await keys.jobSigningPublicKey("tenantA");
    const pubB = await keys.jobSigningPublicKey("tenantB"); // no own key → default
    const pubDefault = await keys.jobSigningPublicKey();
    expect(pubA).not.toBe(pubB);
    expect(pubB).toBe(pubDefault);

    const signedA = await keys.signJobEnvelope(envelope());
    expect(verifyJob(signedA, pubA, "conn1", Date.now())).toMatchObject({ ok: true });
    expect(verifyJob(signedA, pubB, "conn1", Date.now())).toMatchObject({ ok: false, reason: "bad job signature" });
    const signedB = await keys.signJobEnvelope(envelope({ tenantId: "tenantB" }));
    expect(verifyJob(signedB, pubB, "conn1", Date.now())).toMatchObject({ ok: true });
    expect(audit.some((l) => l.includes('"msg":"signer.signed"') && l.includes('"tenantId":"tenantA"'))).toBe(true);
    expect(() => keys.jobSigningKey()).toThrow(/not available/);
  });

  it("surfaces signer rejections (invalid envelope) without signing", async () => {
    const keys = await loadKeys({ JOB_SIGNER: "remote", JOB_SIGNER_URL: url, JOB_SIGNER_TOKEN_FILE: tokenFile });
    const now = Date.now();
    await expect(
      keys.signJobEnvelope(envelope({ notBefore: new Date(now).toISOString(), expiresAt: new Date(now + MAX_JOB_LIFETIME_MS + 1000).toISOString() })),
    ).rejects.toThrow(/lifetime too long/);
  });

  it("fails closed with a wrong token", async () => {
    const bad = join(tmp, "bad-token");
    writeFileSync(bad, "b".repeat(48));
    const keys = await loadKeys({ JOB_SIGNER: "remote", JOB_SIGNER_URL: url, JOB_SIGNER_TOKEN_FILE: bad });
    await expect(keys.signJobEnvelope(envelope())).rejects.toThrow(/unauthorized/);
  });

  it("fails closed when the signer is unreachable", async () => {
    const keys = await loadKeys({ JOB_SIGNER: "remote", JOB_SIGNER_URL: "http://127.0.0.1:1", JOB_SIGNER_TOKEN_FILE: tokenFile });
    await expect(keys.signJobEnvelope(envelope())).rejects.toThrow(/unavailable/);
  });

  it("rejects a signature that does not verify (misbehaving signer)", async () => {
    const realPub = await (await loadKeys({ JOB_SIGNER: "remote", JOB_SIGNER_URL: url, JOB_SIGNER_TOKEN_FILE: tokenFile })).jobSigningPublicKey("tenantA");
    const fake = createServer((req, res) => {
      res.setHeader("content-type", "application/json");
      if (req.url?.startsWith("/v1/public-key")) return res.end(JSON.stringify({ publicKey: realPub }));
      res.end(JSON.stringify({ signature: Buffer.alloc(64).toString("base64"), publicKey: realPub }));
    });
    await new Promise<void>((r) => fake.listen(0, "127.0.0.1", () => r()));
    try {
      const keys = await loadKeys({ JOB_SIGNER: "remote", JOB_SIGNER_URL: `http://127.0.0.1:${(fake.address() as AddressInfo).port}`, JOB_SIGNER_TOKEN_FILE: tokenFile });
      await expect(keys.signJobEnvelope(envelope())).rejects.toThrow(/invalid signature/);
    } finally {
      fake.close();
    }
  });
});
