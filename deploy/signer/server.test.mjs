// Tests for the job signer:  node --test deploy/signer/   (also run in the image build: `--target test`)
import assert from "node:assert/strict";
import { createPublicKey, generateKeyPairSync, verify } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { canonicalJson, createSigner, fingerprint, validateEnvelope } from "./server.mjs";

const TOKEN = "t".repeat(40);
const NOW = Date.parse("2026-10-15T10:00:00.000Z");
const H = 3_600_000;

function newKeyPem() {
  return generateKeyPairSync("ed25519").privateKey.export({ format: "pem", type: "pkcs8" }).toString();
}

function envelope(over = {}) {
  return {
    v: 1,
    id: "job_AAAAAAAAAAAAAAAAAAAA",
    tenantId: "tenantA",
    connectorId: "conn1",
    type: "SYNC_AGENTS",
    payload: {},
    notBefore: new Date(NOW).toISOString(),
    expiresAt: new Date(NOW + 2 * H).toISOString(),
    ...over,
  };
}

const rawToKey = (raw) =>
  createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(raw, "base64")]), format: "der", type: "spki" });

describe("validateEnvelope (rules shared with protocol.ts)", () => {
  const max = 90 * 24 * H;
  it("accepts a well-formed envelope", () => assert.equal(validateEnvelope(envelope(), NOW, max), null));
  it("rejects extra or missing fields", () => {
    assert.match(validateEnvelope({ ...envelope(), extra: 1 }, NOW, max), /unexpected or missing/);
    const { payload: _p, ...missing } = envelope();
    assert.match(validateEnvelope(missing, NOW, max), /unexpected or missing/);
  });
  it("rejects unknown type, bad ids, bad version", () => {
    assert.match(validateEnvelope(envelope({ type: "RUN_SCRIPT" }), NOW, max), /unknown job type/);
    assert.match(validateEnvelope(envelope({ tenantId: "../etc/passwd" }), NOW, max), /tenantId/);
    assert.match(validateEnvelope(envelope({ connectorId: "a b" }), NOW, max), /connectorId/);
    assert.match(validateEnvelope(envelope({ id: "x" }), NOW, max), /job id/);
    assert.match(validateEnvelope(envelope({ v: 2 }), NOW, max), /version/);
    assert.match(validateEnvelope(envelope({ payload: [] }), NOW, max), /payload/);
  });
  it("enforces lifetime <= 72 h, not expired, not too far ahead, canonical ISO dates", () => {
    assert.match(validateEnvelope(envelope({ expiresAt: new Date(NOW + 73 * H).toISOString() }), NOW, max), /lifetime/);
    assert.match(validateEnvelope(envelope({ expiresAt: new Date(NOW).toISOString() }), NOW, max), /expire/);
    assert.match(
      validateEnvelope(envelope({ notBefore: new Date(NOW - 10 * H).toISOString(), expiresAt: new Date(NOW - H).toISOString() }), NOW, max),
      /already expired/,
    );
    assert.match(
      validateEnvelope(envelope({ notBefore: new Date(NOW + 100 * 24 * H).toISOString(), expiresAt: new Date(NOW + 100 * 24 * H + H).toISOString() }), NOW, max),
      /too far/,
    );
    assert.match(validateEnvelope(envelope({ notBefore: "2026-10-15T10:00:00Z" }), NOW, max), /ISO/);
  });
  it("canonicalJson sorts keys and drops undefined (same as protocol.ts)", () => {
    assert.equal(canonicalJson({ b: 1, a: [true, null, "x"], c: undefined }), '{"a":[true,null,"x"],"b":1}');
    assert.throws(() => canonicalJson({ a: Infinity }));
  });
});

describe("signer HTTP service", () => {
  let dir;
  let server;
  let base;
  const lines = [];
  let clock = NOW;

  before(async () => {
    dir = mkdtempSync(join(tmpdir(), "pg-signer-"));
    writeFileSync(join(dir, "default.pem"), newKeyPem());
    writeFileSync(join(dir, "tenantA.pem"), newKeyPem());
    writeFileSync(join(dir, "README.txt"), "ignored");
    server = createSigner({ token: TOKEN, keyDir: dir, ratePerTenantPerMin: 3, ratePerMin: 100, audit: (l) => lines.push(JSON.parse(l)), now: () => clock });
    await new Promise((r) => server.listen(0, "127.0.0.1", r));
    base = `http://127.0.0.1:${server.address().port}`;
  });
  after(() => {
    server.close();
    rmSync(dir, { recursive: true, force: true });
  });

  const call = (path, { body, token = TOKEN, method } = {}) =>
    fetch(base + path, {
      method: method ?? (body === undefined ? "GET" : "POST"),
      headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), "content-type": "application/json" },
      body: body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body),
    });

  it("healthz without auth; everything else requires the token", async () => {
    assert.equal((await call("/healthz", { token: null })).status, 200);
    assert.equal((await call("/v1/public-key", { token: null })).status, 401);
    assert.equal((await call("/v1/public-key", { token: "x".repeat(40) })).status, 401);
    assert.ok(lines.some((l) => l.msg === "signer.denied" && l.reason === "unauthorized"));
  });

  it("serves per-bank public keys with a default fallback", async () => {
    const a = await (await call("/v1/public-key?tenantId=tenantA")).json();
    const b = await (await call("/v1/public-key?tenantId=tenantB")).json();
    const d = await (await call("/v1/public-key")).json();
    assert.equal(a.keyId, "tenantA");
    assert.equal(b.keyId, "default");
    assert.equal(d.publicKey, b.publicKey);
    assert.notEqual(a.publicKey, b.publicKey);
    assert.equal(a.fingerprint, fingerprint(a.publicKey));
    assert.equal((await call("/v1/public-key?tenantId=../x")).status, 400);
  });

  it("signs with the bank's own key; signature verifies over canonicalJson", async () => {
    const env = envelope();
    const res = await call("/v1/sign", { body: { envelope: env } });
    assert.equal(res.status, 200);
    const out = await res.json();
    assert.equal(out.keyId, "tenantA");
    assert.ok(verify(null, Buffer.from(canonicalJson(env)), rawToKey(out.publicKey), Buffer.from(out.signature, "base64")));
    const audit = lines.find((l) => l.msg === "signer.signed" && l.jobId === env.id);
    assert.ok(audit, "every signature is audit-logged");
    assert.equal(audit.tenantId, "tenantA");
    assert.equal(audit.keyFingerprint, out.fingerprint);
    assert.match(audit.envelopeSha256, /^[a-f0-9]{64}$/);

    const other = await (await call("/v1/sign", { body: { envelope: envelope({ tenantId: "tenantB" }) } })).json();
    assert.equal(other.keyId, "default");
  });

  it("refuses invalid envelopes (422) and logs the denial", async () => {
    const res = await call("/v1/sign", { body: { envelope: envelope({ type: "RUN_SCRIPT" }) } });
    assert.equal(res.status, 422);
    assert.ok(lines.some((l) => l.msg === "signer.denied" && l.reason === "unknown job type"));
    assert.equal((await call("/v1/sign", { body: "{not json" })).status, 400);
    assert.equal((await call("/v1/sign", { body: { nope: 1 } })).status, 422);
  });

  it("rate-limits per bank per minute", async () => {
    clock = NOW + 120_000; // new window
    const env = (i) => envelope({ id: `job_RRRRRRRRRRRRRRRRRRR${i}`, tenantId: "tenantC", expiresAt: new Date(NOW + 3 * H).toISOString() });
    const codes = [];
    for (let i = 0; i < 4; i += 1) codes.push((await call("/v1/sign", { body: { envelope: env(i) } })).status);
    assert.deepEqual(codes, [200, 200, 200, 429]);
    assert.equal((await call("/v1/sign", { body: { envelope: envelope({ id: "job_OTHERBANKOTHERBANK1", tenantId: "tenantD", expiresAt: new Date(NOW + 3 * H).toISOString() }) } })).status, 200);
    clock = NOW + 240_000;
    assert.equal((await call("/v1/sign", { body: { envelope: env(9) } })).status, 200);
  });

  it("requireTenantKey: no fallback to the default key", async () => {
    const strict = createSigner({ token: TOKEN, keyDir: dir, requireTenantKey: true, audit: () => {}, now: () => NOW });
    await new Promise((r) => strict.listen(0, "127.0.0.1", r));
    try {
      const url = `http://127.0.0.1:${strict.address().port}`;
      const h = { authorization: `Bearer ${TOKEN}` };
      assert.equal((await fetch(`${url}/v1/public-key?tenantId=tenantB`, { headers: h })).status, 404);
      assert.equal((await fetch(`${url}/v1/public-key?tenantId=tenantA`, { headers: h })).status, 200);
    } finally {
      strict.close();
    }
  });

  it("refuses to start without keys or with a short token", () => {
    const empty = mkdtempSync(join(tmpdir(), "pg-signer-empty-"));
    try {
      assert.throws(() => createSigner({ token: TOKEN, keyDir: empty }), /no signing keys/);
      assert.throws(() => createSigner({ token: "short", keyDir: dir }), /token/);
    } finally {
      rmSync(empty, { recursive: true, force: true });
    }
  });
});
