/**
 * Connector enrolment + signed-request authentication (protocol.ts §1–2) against a real database.
 */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { TENANT_A, TENANT_B, configureTestEnv, resetDb } from "./helpers";
import { enrollBody, makeConnectorKey, sessionUserOf, signedParts, type ConnectorKey } from "./connector-helpers";

const repoDir = mkdtempSync(join(tmpdir(), "pg-conn-auth-"));
configureTestEnv({ REPO_DIR: repoDir, PUBLIC_BASE_URL: "https://patchgate.example.test" });
const { prisma } = await import("@/lib/db");
const { createEnrollmentCode, revokeConnector, updateConnectorLimits } = await import("@/lib/connector/admin");
const { redeemEnrollment, ENROLL_CODE_TTL_MS } = await import("@/lib/connector/enroll");
const { authenticateConnector, purgeExpiredNonces } = await import("@/lib/connector/auth");
const { recordHeartbeat } = await import("@/lib/connector/heartbeat");
const { jobKeyFingerprint, jobSigningKey, jobSigningPublicKey } = await import("@/lib/connector/keys");
const { ENROLL_CODE_RE, MAX_CLOCK_SKEW_MS, verifyJob } = await import("@/lib/connector/protocol");
const { claimJobs, enqueueJob } = await import("@/lib/connector/queue");
const { withTenant } = await import("@/lib/tenancy");
const { verifyAuditLog } = await import("@/lib/audit/service");

beforeEach(() => resetDb(prisma));
afterAll(async () => {
  await prisma.$disconnect();
  rmSync(repoDir, { recursive: true, force: true });
});

async function platformAdmin() {
  return sessionUserOf(await prisma.user.create({ data: { upn: `admin-${Math.random()}@pg`, name: "Admin", role: "ADMIN" } }));
}

async function enrolled(tenantId = TENANT_A, name = "HQ"): Promise<{ connectorId: string; key: ConnectorKey }> {
  const { code } = await createEnrollmentCode(await platformAdmin(), { tenantId, name });
  const key = makeConnectorKey();
  const r = await redeemEnrollment(enrollBody(code, key));
  return { connectorId: r.connectorId, key };
}

describe("enrolment", () => {
  it("creates a single-use 100-bit code (hash stored), shows the exact init command, and enrols with proof of possession", async () => {
    const admin = await platformAdmin();
    const created = await createEnrollmentCode(admin, { tenantId: TENANT_A, name: "Head office DC" });
    expect(created.code).toMatch(ENROLL_CODE_RE);
    expect(created.initCommand).toContain(`PATCHGATE_ENROLL_CODE=${created.code}`);
    expect(created.initCommand).toContain("--server https://patchgate.example.test");
    // the bank's job-key fingerprint is part of the command (pinned by the connector) and shown to the admin
    expect(created.fingerprint).toBe(jobKeyFingerprint(await jobSigningPublicKey(TENANT_A)));
    expect(created.initCommand).toContain(`--job-key-fingerprint ${created.fingerprint}`);
    const row = await prisma.connectorEnrollment.findFirstOrThrow();
    expect(row.id).not.toContain(created.code);
    expect(row.id).toMatch(/^[a-f0-9]{64}$/);

    const key = makeConnectorKey();
    const r = await redeemEnrollment(enrollBody(created.code, key, "1.0.0"));
    expect(r).toEqual({ connectorId: expect.stringMatching(/^[A-Za-z0-9_-]{1,64}$/), tenantId: TENANT_A, name: "Head office DC", jobSigningPublicKey: jobSigningKey().publicKeyRaw });
    const c = await prisma.connector.findUniqueOrThrow({ where: { id: r.connectorId } });
    expect(c).toMatchObject({ tenantId: TENANT_A, publicKey: key.publicRaw, status: "ACTIVE", version: "1.0.0" });

    // second use of the same code fails
    await expect(redeemEnrollment(enrollBody(created.code, makeConnectorKey()))).rejects.toMatchObject({ status: 403 });
    // audited on the BANK chain, not the platform chain
    const actions = (await prisma.auditEvent.findMany({ where: { tenantId: TENANT_A }, orderBy: { seq: "asc" } })).map((e) => e.action);
    expect(actions).toEqual(["connector.enrollment_created", "connector.enrolled"]);
    expect(await verifyAuditLog(TENANT_A)).toMatchObject({ valid: true });
  });

  it("returns the bank's job-signing key; jobs queued for that bank's connector verify with exactly that key", async () => {
    for (const tenantId of [TENANT_A, TENANT_B]) {
      const { code } = await createEnrollmentCode(await platformAdmin(), { tenantId, name: `Site ${tenantId}` });
      const r = await redeemEnrollment(enrollBody(code, makeConnectorKey()));
      expect(r.jobSigningPublicKey).toBe(await jobSigningPublicKey(tenantId));
      await withTenant(tenantId, (tx) =>
        enqueueJob(tx, { tenantId, connectorId: r.connectorId, type: "SCAN", payload: { agentIds: ["agentKEY00001"] }, expiresAt: new Date(Date.now() + 3_600_000) }),
      );
      const [job] = await claimJobs(tenantId, r.connectorId);
      // what the connector does with every job: verify against the key it pinned at enrolment
      expect(verifyJob(job, r.jobSigningPublicKey, r.connectorId, Date.now())).toMatchObject({ ok: true, type: "SCAN" });
      expect(verifyJob({ ...job, payload: { agentIds: ["agentOTHER0001"] } }, r.jobSigningPublicKey, r.connectorId, Date.now())).toMatchObject({ ok: false });
    }
  });

  it("only one of two concurrent redemptions of the same code wins", async () => {
    const { code } = await createEnrollmentCode(await platformAdmin(), { tenantId: TENANT_A, name: "HQ" });
    const results = await Promise.allSettled([redeemEnrollment(enrollBody(code, makeConnectorKey())), redeemEnrollment(enrollBody(code, makeConnectorKey()))]);
    expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
    expect(await prisma.connector.count()).toBe(1);
  });

  it("rejects expired codes, a wrong proof, a key that is not the one proven, and non-admins", async () => {
    const admin = await platformAdmin();
    const { code } = await createEnrollmentCode(admin, { tenantId: TENANT_A, name: "HQ" }, undefined, new Date(Date.now() - ENROLL_CODE_TTL_MS - 1000));
    await expect(redeemEnrollment(enrollBody(code, makeConnectorKey()))).rejects.toMatchObject({ status: 403 });

    const fresh = await createEnrollmentCode(admin, { tenantId: TENANT_A, name: "Branch" });
    const k1 = makeConnectorKey();
    const k2 = makeConnectorKey();
    const forged = { ...enrollBody(fresh.code, k1), publicKey: k2.publicRaw }; // proof by k1, claims k2
    await expect(redeemEnrollment(forged)).rejects.toMatchObject({ status: 403, message: "proof of key possession failed" });
    await expect(redeemEnrollment({ code: "nope" })).rejects.toMatchObject({ status: 400 });
    // the failed attempts did not consume the code
    await expect(redeemEnrollment(enrollBody(fresh.code, k1))).resolves.toMatchObject({ name: "Branch" });

    const bankAdmin = sessionUserOf(await prisma.user.create({ data: { upn: "ba@a", name: "BA", role: "ADMIN", tenantId: TENANT_A } }));
    await expect(createEnrollmentCode(bankAdmin, { tenantId: TENANT_A, name: "X1" })).rejects.toMatchObject({ status: 403 });
  });

  it("re-enrolment is two-phase: the old key keeps working until the new key signs its first request", async () => {
    const first = await enrolled(TENANT_A, "HQ");
    const jobs = (k: ConnectorKey, id: string) => authenticateConnector(signedParts(k, id, "GET", "/api/connector/v1/jobs?wait=0"));
    // a re-enrolment whose init is then refused on the connector side (e.g. wrong fingerprint) …
    const second = await enrolled(TENANT_A, "HQ");
    expect(second.connectorId).toBe(first.connectorId);
    // … does NOT lock the working connector out
    await expect(jobs(first.key, first.connectorId)).resolves.toMatchObject({ id: first.connectorId });
    expect(await prisma.connector.findUniqueOrThrow({ where: { id: first.connectorId } })).toMatchObject({ publicKey: first.key.publicRaw, pendingPublicKey: second.key.publicRaw });
    // the new key proves possession → it becomes THE key; the old one stops working
    await expect(jobs(second.key, second.connectorId)).resolves.toMatchObject({ id: first.connectorId });
    expect(await prisma.connector.findUniqueOrThrow({ where: { id: first.connectorId } })).toMatchObject({ publicKey: second.key.publicRaw, pendingPublicKey: null, status: "ACTIVE" });
    await expect(jobs(first.key, first.connectorId)).rejects.toMatchObject({ status: 401 });
    const actions = (await prisma.auditEvent.findMany({ where: { tenantId: TENANT_A, entity: "Connector" }, orderBy: { seq: "asc" } })).map((e) => e.action);
    expect(actions).toEqual(["connector.enrolled", "connector.rekey_pending", "connector.rekey_activated"]);
    expect(await verifyAuditLog(TENANT_A)).toMatchObject({ valid: true });
  });

  it("re-enrolling a REVOKED site: the old key stays revoked, the new key activates the connector", async () => {
    const first = await enrolled(TENANT_A, "HQ");
    await revokeConnector(await platformAdmin(), first.connectorId, "lost laptop");
    const second = await enrolled(TENANT_A, "HQ");
    const jobs = (k: ConnectorKey) => authenticateConnector(signedParts(k, first.connectorId, "GET", "/api/connector/v1/jobs?wait=0"));
    await expect(jobs(first.key)).rejects.toMatchObject({ status: 403 });
    await expect(jobs(second.key)).resolves.toMatchObject({ id: first.connectorId });
    await expect(jobs(first.key)).rejects.toMatchObject({ status: 401 });
  });
});

describe("signed requests", () => {
  it("accepts a correctly signed request and records lastSeenAt", async () => {
    const { connectorId, key } = await enrolled();
    await prisma.connector.update({ where: { id: connectorId }, data: { lastSeenAt: null } });
    const c = await authenticateConnector(signedParts(key, connectorId, "POST", "/api/connector/v1/heartbeat", '{"a":1}'));
    expect(c).toMatchObject({ id: connectorId, tenantId: TENANT_A, maxConcurrentInstalls: 50 });
    expect((await prisma.connector.findUniqueOrThrow({ where: { id: connectorId } })).lastSeenAt).not.toBeNull();
  });

  it("rejects a bad signature, a tampered body / path / query, a foreign key and an unknown connector", async () => {
    const { connectorId, key } = await enrolled();
    const ok = signedParts(key, connectorId, "POST", "/api/connector/v1/jobs/x/result", '{"ok":true}');
    await expect(authenticateConnector({ ...ok, body: new TextEncoder().encode('{"ok":false}') })).rejects.toMatchObject({ status: 401, reason: "bad signature" });
    await expect(authenticateConnector({ ...signedParts(key, connectorId, "GET", "/api/connector/v1/audit?after=1"), pathWithQuery: "/api/connector/v1/audit?after=0" })).rejects.toMatchObject({ reason: "bad signature" });
    await expect(authenticateConnector({ ...signedParts(key, connectorId, "GET", "/api/connector/v1/jobs"), method: "POST" })).rejects.toMatchObject({ reason: "bad signature" });
    await expect(authenticateConnector(signedParts(makeConnectorKey(), connectorId, "GET", "/api/connector/v1/jobs"))).rejects.toMatchObject({ reason: "bad signature" });
    await expect(authenticateConnector(signedParts(key, "doesnotexist", "GET", "/api/connector/v1/jobs"))).rejects.toMatchObject({ reason: "unknown connector" });
  });

  it("rejects replays (same nonce) and clock skew beyond 5 minutes", async () => {
    const { connectorId, key } = await enrolled();
    const parts = signedParts(key, connectorId, "GET", "/api/connector/v1/jobs?wait=0");
    await authenticateConnector(parts);
    await expect(authenticateConnector(parts)).rejects.toMatchObject({ status: 401, reason: "replayed nonce" });

    const old = signedParts(key, connectorId, "GET", "/api/connector/v1/jobs", "", { timestamp: Date.now() - MAX_CLOCK_SKEW_MS - 5_000 });
    await expect(authenticateConnector(old)).rejects.toMatchObject({ reason: "timestamp outside the allowed clock skew" });
    const future = signedParts(key, connectorId, "GET", "/api/connector/v1/jobs", "", { timestamp: Date.now() + MAX_CLOCK_SKEW_MS + 5_000 });
    await expect(authenticateConnector(future)).rejects.toMatchObject({ reason: "timestamp outside the allowed clock skew" });
    // nonces are kept until they can no longer be replayed, then purged
    expect(await purgeExpiredNonces(new Date(Date.now() + 2 * MAX_CLOCK_SKEW_MS + 120_000))).toBeGreaterThanOrEqual(1);
  });

  it("a revoked connector is rejected immediately (403); a suspended bank too", async () => {
    const admin = await platformAdmin();
    const a = await enrolled(TENANT_A, "HQ");
    const b = await enrolled(TENANT_B, "HQ");
    await revokeConnector(admin, a.connectorId, "laptop stolen");
    await expect(authenticateConnector(signedParts(a.key, a.connectorId, "GET", "/api/connector/v1/jobs"))).rejects.toMatchObject({ status: 403, reason: "connector revoked" });
    await expect(revokeConnector(admin, a.connectorId)).rejects.toMatchObject({ status: 409 });

    await prisma.tenant.update({ where: { id: TENANT_B }, data: { active: false } });
    await expect(authenticateConnector(signedParts(b.key, b.connectorId, "GET", "/api/connector/v1/jobs"))).rejects.toMatchObject({ status: 403, reason: "bank suspended" });
    const ev = await prisma.auditEvent.findFirstOrThrow({ where: { action: "connector.revoked" } });
    expect(ev).toMatchObject({ tenantId: TENANT_A, actor: admin.upn });
  });
});

describe("heartbeat and limits", () => {
  it("stores health and answers with the bank's limits (audited when the admin changes them)", async () => {
    const admin = await platformAdmin();
    const { connectorId } = await enrolled();
    const authed = { id: connectorId, tenantId: TENANT_A, name: "HQ", maxConcurrentInstalls: 50, bandwidthLimitMbps: null };
    await updateConnectorLimits(admin, connectorId, { maxConcurrentInstalls: 7, bandwidthLimitMbps: 200 });
    const reply = await recordHeartbeat(authed, {
      version: "1.0.1",
      cacheBaseUrl: "https://pgcache.bank.local:8443/repo",
      cache: { files: 3, bytes: 1024, freeBytes: 10_000 },
      tactical: { reachable: true, agents: 12, error: null },
      siem: { configured: false, lastForwardedSeq: null, error: null },
    });
    expect(reply).toMatchObject({ maxConcurrentInstalls: 7, bandwidthLimitMbps: 200, serverTime: expect.any(String) });
    const c = await prisma.connector.findUniqueOrThrow({ where: { id: connectorId } });
    expect(c).toMatchObject({ version: "1.0.1", cacheBaseUrl: "https://pgcache.bank.local:8443/repo" });
    expect(c.heartbeat).toMatchObject({ tactical: { reachable: true, agents: 12 } });
    await expect(recordHeartbeat(authed, { version: 1 })).rejects.toMatchObject({ status: 400 });
    await expect(updateConnectorLimits(admin, connectorId, { maxConcurrentInstalls: 0 })).rejects.toThrow();
    const actions = (await prisma.auditEvent.findMany({ where: { tenantId: TENANT_A }, orderBy: { seq: "asc" } })).map((e) => e.action);
    expect(actions).toContain("connector.limits_updated");
    expect(actions).toContain("connector.reported_config");
  });
});
