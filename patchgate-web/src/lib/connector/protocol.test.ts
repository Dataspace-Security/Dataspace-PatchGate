import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  canonicalJson,
  canonicalRequest,
  enrollProofMessage,
  rawFromPublicKey,
  signJob,
  signRequest,
  timestampFresh,
  verifyJob,
  verifyRequest,
  type JobEnvelope,
} from "./protocol";

const conn = generateKeyPairSync("ed25519");
const jobKey = generateKeyPairSync("ed25519");
const connPub = rawFromPublicKey(conn.publicKey);
const jobPub = rawFromPublicKey(jobKey.publicKey);
const NOW = Date.parse("2026-10-15T10:00:00Z");

const env = (over: Partial<JobEnvelope> = {}): JobEnvelope => ({
  v: 1,
  id: "job1",
  tenantId: "t1",
  connectorId: "c1",
  type: "SCAN",
  payload: { agentIds: ["agentAAAA1111"] },
  notBefore: "2026-10-15T09:59:00Z",
  expiresAt: "2026-10-15T11:00:00Z",
  ...over,
});

describe("canonicalJson", () => {
  it("sorts keys recursively, drops undefined, keeps arrays in order", () => {
    expect(canonicalJson({ b: 1, a: { d: [3, { y: 1, x: 2 }], c: "s" }, u: undefined })).toBe('{"a":{"c":"s","d":[3,{"x":2,"y":1}]},"b":1}');
  });
  it("rejects non-finite numbers", () => {
    expect(() => canonicalJson({ a: Number.NaN })).toThrow();
  });
});

describe("request signatures", () => {
  const body = JSON.stringify({ hello: "world" });
  const sig = signRequest(conn.privateKey, "post", "/api/connector/v1/heartbeat", String(NOW), "nonce-nonce-nonce1", body);
  it("verifies an untampered request", () => {
    expect(verifyRequest(connPub, sig, "POST", "/api/connector/v1/heartbeat", String(NOW), "nonce-nonce-nonce1", body)).toBe(true);
  });
  it.each([
    ["method", ["GET", "/api/connector/v1/heartbeat", String(NOW), "nonce-nonce-nonce1", body]],
    ["path", ["POST", "/api/connector/v1/jobs", String(NOW), "nonce-nonce-nonce1", body]],
    ["timestamp", ["POST", "/api/connector/v1/heartbeat", String(NOW + 1), "nonce-nonce-nonce1", body]],
    ["nonce", ["POST", "/api/connector/v1/heartbeat", String(NOW), "nonce-nonce-nonce2", body]],
    ["body", ["POST", "/api/connector/v1/heartbeat", String(NOW), "nonce-nonce-nonce1", body + " "]],
  ] as const)("rejects a changed %s", (_n, [m, p, t, n, b]) => {
    expect(verifyRequest(connPub, sig, m, p, t, n, b)).toBe(false);
  });
  it("rejects another key and garbage", () => {
    expect(verifyRequest(jobPub, sig, "POST", "/api/connector/v1/heartbeat", String(NOW), "nonce-nonce-nonce1", body)).toBe(false);
    expect(verifyRequest(connPub, "garbage", "POST", "/x", "1", "n", "")).toBe(false);
    expect(verifyRequest("not-a-key", sig, "POST", "/x", "1", "n", "")).toBe(false);
  });
  it("canonical request format is stable (cross-implementation vector)", () => {
    expect(canonicalRequest("get", "/api/connector/v1/jobs?wait=25", "1792000000000", "abcdefghijklmnop", "")).toBe(
      "PGC1\nGET\n/api/connector/v1/jobs?wait=25\n1792000000000\nabcdefghijklmnop\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
    expect(enrollProofMessage("AAAA-BBBB-CCCC-DDDD-EEEE", "pk")).toBe("PGC1-ENROLL\nAAAA-BBBB-CCCC-DDDD-EEEE\npk");
  });
  it("timestamps must be within 5 minutes", () => {
    expect(timestampFresh(String(NOW - 299_000), NOW)).toBe(true);
    expect(timestampFresh(String(NOW + 301_000), NOW)).toBe(false);
    expect(timestampFresh("abc", NOW)).toBe(false);
  });
});

describe("signed jobs", () => {
  it("accepts a valid job and returns the parsed payload", () => {
    const r = verifyJob(signJob(jobKey.privateKey, env()), jobPub, "c1", NOW);
    expect(r).toEqual({ ok: true, type: "SCAN", payload: { agentIds: ["agentAAAA1111"] } });
  });
  it("rejects a modified payload (e.g. a TLS-inspecting proxy adding an agent)", () => {
    const j = signJob(jobKey.privateKey, env());
    const tampered = { ...j, payload: { agentIds: ["agentAAAA1111", "agentBBBB2222"] } };
    expect(verifyJob(tampered, jobPub, "c1", NOW)).toEqual({ ok: false, reason: "bad job signature" });
  });
  it("rejects jobs signed by another key, for another connector, expired, or not yet valid", () => {
    expect(verifyJob(signJob(conn.privateKey, env()), jobPub, "c1", NOW).ok).toBe(false);
    expect(verifyJob(signJob(jobKey.privateKey, env()), jobPub, "c2", NOW)).toMatchObject({ reason: "job is for another connector" });
    expect(verifyJob(signJob(jobKey.privateKey, env({ expiresAt: "2026-10-15T09:00:00Z" })), jobPub, "c1", NOW)).toMatchObject({ reason: "job expired" });
    expect(verifyJob(signJob(jobKey.privateKey, env({ notBefore: "2026-10-15T12:00:00Z" })), jobPub, "c1", NOW)).toMatchObject({ reason: "job not yet valid" });
  });
  it("rejects a correctly signed job whose payload breaks the typed schema", () => {
    const bad = signJob(jobKey.privateKey, env({ type: "DEPLOY_WINDOWS", payload: { agentId: "agentAAAA1111", guids: ["not-a-guid"], rebootPolicy: "NEVER" } }));
    expect(verifyJob(bad, jobPub, "c1", NOW)).toMatchObject({ ok: false, reason: expect.stringMatching(/invalid payload/) });
    const extra = signJob(jobKey.privateKey, env({ payload: { agentIds: ["agentAAAA1111"], script: "rm -rf /" } }));
    expect(verifyJob(extra, jobPub, "c1", NOW).ok).toBe(false); // strict: unknown fields rejected
  });
  it("rejects jobs valid for longer than the maximum lifetime", () => {
    const long = signJob(jobKey.privateKey, env({ notBefore: "2026-10-15T09:00:00Z", expiresAt: "2026-10-19T09:00:00Z" }));
    expect(verifyJob(long, jobPub, "c1", NOW)).toMatchObject({ reason: "job lifetime too long" });
  });
  it("rejects unknown job types even if signed", () => {
    expect(verifyJob(signJob(jobKey.privateKey, env({ type: "RUN_COMMAND" as never })), jobPub, "c1", NOW)).toMatchObject({ reason: "unknown job type" });
  });
});
