/**
 * The whole connector pipeline as a NON-owner, NON-superuser, NOBYPASSRLS database role (like production's
 * patchgate_app): Row-Level Security is FORCED on Connector / ConnectorEnrollment / ConnectorJob, so every
 * connector code path must go through withTenant / withPlatform — anything that forgot would see nothing.
 */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { TacticalClient } from "@/lib/tactical/client";
import { TENANT_A, TENANT_B, configureTestEnv, resetDb } from "./helpers";
import { enrollBody, makeConnectorKey, sessionUserOf, signedParts, writeRepoFile } from "./connector-helpers";

const APP_ROLE = "patchgate_app_conn_test";
const APP_PASSWORD = "app-role-conn-test-only-0123456789";
const repoDir = mkdtempSync(join(tmpdir(), "pg-conn-rls-"));

configureTestEnv({ REPO_DIR: repoDir, LOG_LEVEL: "error" });
const adminUrl = process.env.DATABASE_URL!;
const { PrismaClient } = await import("@prisma/client");
const admin = new PrismaClient({ datasourceUrl: adminUrl }); // superuser: fixtures + role setup only

await admin.$executeRawUnsafe(`DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${APP_ROLE}') THEN
    CREATE ROLE ${APP_ROLE} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
END
$$`);
await admin.$executeRawUnsafe(`ALTER ROLE ${APP_ROLE} PASSWORD '${APP_PASSWORD}'`);
await admin.$executeRawUnsafe(`GRANT USAGE ON SCHEMA public TO ${APP_ROLE}`);
await admin.$executeRawUnsafe(`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ${APP_ROLE}`);
await admin.$executeRawUnsafe(`GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO ${APP_ROLE}`);
await admin.$executeRawUnsafe(`GRANT patchgate_tenant TO ${APP_ROLE}`);

const appUrl = new URL(adminUrl);
appUrl.username = APP_ROLE;
appUrl.password = APP_PASSWORD;
process.env.DATABASE_URL = appUrl.toString();

const { prisma } = await import("@/lib/db");
const { withTenant } = await import("@/lib/tenancy");
const { createEnrollmentCode, revokeConnector, listConnectors, connectorHealth } = await import("@/lib/connector/admin");
const { redeemEnrollment } = await import("@/lib/connector/enroll");
const { authenticateConnector } = await import("@/lib/connector/auth");
const { recordHeartbeat } = await import("@/lib/connector/heartbeat");
const { claimJobs } = await import("@/lib/connector/queue");
const { acceptResult } = await import("@/lib/connector/results");
const { resolvePackageDownload } = await import("@/lib/connector/packages");
const { auditPage } = await import("@/lib/connector/audit-relay");
const { createChangeRequest, applyAction } = await import("@/lib/approvals/service");
const { startDeployment } = await import("@/lib/deploy/start");
const { runWorkerTick } = await import("@/lib/deploy/worker");
const { verifyAuditLog } = await import("@/lib/audit/service");

beforeEach(() => resetDb(admin));
afterAll(async () => {
  await prisma.$disconnect();
  await admin.$disconnect();
  rmSync(repoDir, { recursive: true, force: true });
});

const noTactical = {
  listAgents: vi.fn(async () => []),
  getAgent: vi.fn(),
  scanUpdates: vi.fn(),
  getUpdates: vi.fn(),
  setUpdateAction: vi.fn(),
  installApproved: vi.fn(),
  getSoftware: vi.fn(),
  refreshSoftware: vi.fn(),
  runScript: vi.fn(),
} as unknown as TacticalClient;

async function tick() {
  const r = await runWorkerTick({ tactical: noTactical, siem: null });
  expect(r.ok, JSON.stringify(r.steps)).toBe(true);
  return r;
}

async function enrol(tenantId: string, name: string) {
  const platformAdmin = sessionUserOf(await admin.user.upsert({ where: { upn: "admin@pg" }, update: {}, create: { upn: "admin@pg", name: "A", role: "ADMIN" } }));
  const { code } = await createEnrollmentCode(platformAdmin, { tenantId, name });
  const key = makeConnectorKey();
  const r = await redeemEnrollment(enrollBody(code, key));
  const authed = await authenticateConnector(signedParts(key, r.connectorId, "POST", "/api/connector/v1/heartbeat", "{}"));
  return { key, connector: authed, platformAdmin };
}

const heartbeat = { version: "1.0.0", cacheBaseUrl: "https://pgcache.bank.local:8443/repo", cache: { files: 0, bytes: 0 }, tactical: { reachable: true, agents: 1 } };

describe("connector tables under FORCED row-level security", () => {
  it("unscoped queries see no connector rows; scoped ones see exactly their bank", async () => {
    await enrol(TENANT_A, "HQ");
    await enrol(TENANT_B, "HQ");
    const [me] = await prisma.$queryRaw<{ u: string; su: boolean }[]>`SELECT current_user AS u, rolsuper AS su FROM pg_roles WHERE rolname = current_user`;
    expect(me).toEqual({ u: APP_ROLE, su: false });
    expect(await prisma.connector.count()).toBe(0);
    expect(await prisma.connectorEnrollment.count()).toBe(0);
    expect(await withTenant(TENANT_A, (tx) => tx.connector.findMany({ select: { tenantId: true } }))).toEqual([{ tenantId: TENANT_A }]);
    expect(await listConnectors({ kind: "platform" })).toHaveLength(2);
    expect(await listConnectors({ kind: "tenant", tenantId: TENANT_B })).toEqual([expect.objectContaining({ tenantId: TENANT_B })]);
    await expect(
      withTenant(TENANT_A, (tx) => tx.connectorJob.create({ data: { id: "job_x", tenantId: TENANT_B, connectorId: "c", type: "SCAN", payload: {}, signature: "s", expiresAt: new Date() } })),
    ).rejects.toThrow(/row-level security/);
  });

  it("enrol → heartbeat → SYNC → approved CR → CACHE_PACKAGE → DEPLOY_PACKAGE → COLLECT → SUCCEEDED, all as the app role", async () => {
    const { connector: c, key, platformAdmin } = await enrol(TENANT_A, "HQ");
    await recordHeartbeat(c, heartbeat);

    // tick schedules SYNC_AGENTS (and nothing else: no PCs yet)
    await tick();
    const [sync] = await claimJobs(c.tenantId, c.id);
    expect(sync.type).toBe("SYNC_AGENTS");
    await acceptResult(c, sync.id, { ok: true, result: { agents: [{ agentId: "agentRLS00001", hostname: "PC1", goarch: "amd64", version: "2.10.0" }] } });
    await tick(); // applies the result (+ schedules SCAN / COLLECT for the new PC)
    const ep = await admin.endpoint.findFirstOrThrow({ where: { tacticalAgentId: "agentRLS00001" } });
    expect(ep).toMatchObject({ tenantId: TENANT_A, connectorId: c.id });
    await admin.connectorJob.updateMany({ where: { type: { in: ["SCAN", "COLLECT"] } }, data: { status: "CANCELLED" } });

    // an approved change request with a third-party package
    const file = writeRepoFile(repoDir, "pkgs/7zip/24.08/7z2408-x64.msi", "rls msi bytes");
    const app = await admin.app.create({ data: { wingetId: "7zip.7zip", displayName: "7-Zip", inventoryMatch: "^7-Zip", expectedPublisher: "O=Igor Pavlov", allowedDomains: [] } });
    const v = await admin.appVersion.create({
      data: { appId: app.id, version: "24.08", installerUrl: "https://github.com/x.msi", sha256: file.sha256, silentArgs: "", verification: "VERIFIED", repoPath: file.repoPath, availableAt: new Date(0), signerOrg: "Igor Pavlov" },
    });
    const patch = await admin.patch.create({ data: { kind: "THIRD_PARTY", externalId: "7zip.7zip@24.08", title: "7-Zip 24.08", appVersionId: v.id } });
    await admin.tenantApp.create({ data: { tenantId: TENANT_A, appId: app.id, enabledBy: "admin@pg" } });
    const ring = await admin.ring.create({ data: { tenantId: TENANT_A, name: "R0", wsusGroup: "R0", order: 0 } });
    await admin.endpoint.update({ where: { id: ep.id }, data: { ringId: ring.id } });
    const maker = sessionUserOf(await admin.user.create({ data: { upn: "op@pg", name: "Op", role: "ADMIN" } }));
    const checker = sessionUserOf(await admin.user.create({ data: { upn: "ap@a", name: "Ap", role: "ADMIN", tenantId: TENANT_A } }));
    const cr = await createChangeRequest(maker, TENANT_A, { title: "7-Zip", ringId: ring.id, patchIds: [patch.id] });
    await applyAction(maker, TENANT_A, cr.id, "submit");
    await applyAction(checker, TENANT_A, cr.id, "approve");
    await startDeployment(checker, TENANT_A, cr.id);

    await tick();
    const [cache] = await claimJobs(c.tenantId, c.id);
    expect(cache.type).toBe("CACHE_PACKAGE");
    expect(await resolvePackageDownload(c, file.sha256)).toMatchObject({ size: file.size });
    await acceptResult(c, cache.id, { ok: true, result: { sha256: file.sha256, size: file.size, cachedPath: file.repoPath } });
    await tick();
    await admin.connectorJob.updateMany({ where: { type: "DEPLOY_PACKAGE" }, data: { notBefore: new Date(Date.now() - 1000) } });
    const [install] = await claimJobs(c.tenantId, c.id);
    expect(install.type).toBe("DEPLOY_PACKAGE");
    await acceptResult(c, install.id, { ok: true, result: { outcome: "INSTALLED" } });
    await tick(); // SENT + confirm COLLECT queued
    const claimed = await claimJobs(c.tenantId, c.id);
    const collect = claimed.find((j) => j.type === "COLLECT")!;
    await acceptResult(c, collect.id, { ok: true, result: { agents: [{ agentId: "agentRLS00001", updates: [], software: [{ name: "7-Zip 24.08", version: "24.08" }], agent: { version: "2.10.0" } }] } });
    await tick();
    expect((await admin.deployment.findFirstOrThrow()).status).toBe("SUCCEEDED");
    expect((await admin.changeRequest.findUniqueOrThrow({ where: { id: cr.id } })).status).toBe("COMPLETED");

    // the relay sees this bank's chain (and only it); the chain verifies
    const page = await auditPage(c, BigInt(0), 500);
    expect(page.records.map((r) => r.action)).toEqual(expect.arrayContaining(["connector.enrolled", "change_request.deploy", "deployment.succeeded", "change_request.finalise"]));
    expect(await verifyAuditLog(TENANT_A)).toMatchObject({ valid: true });
    expect(await connectorHealth(TENANT_A)).toMatchObject({ total: 1, online: 1 });

    // revoke: next request is refused
    await revokeConnector(platformAdmin, c.id, "test");
    await expect(authenticateConnector(signedParts(key, c.id, "GET", "/api/connector/v1/jobs"))).rejects.toMatchObject({ status: 403 });
  });
});
