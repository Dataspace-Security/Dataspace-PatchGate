/**
 * Security regressions for shared-platform data (findings #9 WSUS, #9/#2 discovery allow-list approval,
 * #10 public /repo, #6 regex boundary) against real PostgreSQL.
 * Run: TEST_DATABASE_URL=postgresql://…/patchgate_test_wu npm run test:int -- src/test/security-platform.int.test.ts
 */
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";
import { TENANT_A, TENANT_B, configureTestEnv, resetDb } from "./helpers";

const repoDir = mkdtempSync(join(tmpdir(), "pg-sec-"));
configureTestEnv({ REPO_DIR: repoDir });

const repoPublicSwitch = vi.hoisted(() => ({ value: false }));
vi.mock("next/server", () => ({ connection: async () => undefined }));
vi.mock("@/lib/env", async (orig) => {
  const real = await orig<typeof import("@/lib/env")>();
  return { ...real, repoPublic: () => repoPublicSwitch.value };
});

const { prisma } = await import("@/lib/db");
const { verifyAuditLog } = await import("@/lib/audit/service");
const { ingestWsusCatalog, wsusBatchSchema } = await import("@/lib/wsus/catalog");
const { manageDiscovered, listAllowlistRequests, approveAllowlistRequest, declineAllowlistRequest } = await import("@/lib/discovery/service");
const { repoPublic } = await vi.importActual<typeof import("@/lib/env")>("@/lib/env");
const { safeRegexSchema } = await import("@/lib/safe-regex");
const repoRoute = await import("@/app/repo/[...path]/route");

beforeEach(async () => {
  await prisma.$executeRawUnsafe(`DELETE FROM "WinUpdateFile"`);
  await prisma.$executeRawUnsafe(`DELETE FROM "WinUpdate"`);
  await resetDb(prisma);
});
afterAll(async () => {
  await prisma.$disconnect();
  rmSync(repoDir, { recursive: true, force: true });
});

const G1 = "c0ffee00-0000-4000-8000-000000000001";
const G2 = "c0ffee00-0000-4000-8000-000000000002";

describe("finding #9: WSUS ingestion is create-only and legacy-bank scoped", () => {
  it("never overwrites shared Patch metadata; creates new rows; audits on the legacy bank's chain", async () => {
    // G1 already exists (bound from the Microsoft Update Catalog, seen by every bank)
    await prisma.patch.create({ data: { kind: "WINDOWS", externalId: G1, kb: "KB5044284", title: "2024-10 Cumulative Update (KB5044284)", severity: "CRITICAL", classification: "Security Updates" } });
    await prisma.winUpdate.create({ data: { id: G1, revision: 0, title: "x", catalogState: "RESOLVED" } });
    const batch = wsusBatchSchema.parse({
      updates: [
        { updateId: G1, title: "Optional preview (harmless)", kb: "5000001", msrcSeverity: "Low", released: "2024-10-08T00:00:00Z", cves: ["CVE-2024-0001"], supersededBy: G2 },
        { updateId: G2, title: "New CU", kb: "5000002", msrcSeverity: "Important" },
      ],
    });
    expect(await ingestWsusCatalog(batch.updates)).toEqual({ upserted: 1, superseded: 0 });
    const p1 = await prisma.patch.findUniqueOrThrow({ where: { externalId: G1 } });
    expect(p1).toMatchObject({ kb: "KB5044284", title: "2024-10 Cumulative Update (KB5044284)", severity: "CRITICAL", supersededById: null });
    expect(p1.releasedAt?.toISOString()).toBe("2024-10-08T00:00:00.000Z"); // empty fields may be filled
    expect(p1.cves).toEqual(["CVE-2024-0001"]);
    expect(await prisma.patch.findUniqueOrThrow({ where: { externalId: G2 } })).toMatchObject({ kb: "KB5000002", severity: "IMPORTANT" });

    // re-ingest with other metadata: still nothing overwritten
    await ingestWsusCatalog(wsusBatchSchema.parse({ updates: [{ updateId: G2, title: "renamed", kb: "5999999", msrcSeverity: "Low" }] }).updates);
    expect(await prisma.patch.findUniqueOrThrow({ where: { externalId: G2 } })).toMatchObject({ title: "New CU", kb: "KB5000002" });

    const ev = await prisma.auditEvent.findMany({ where: { action: "wsus.catalog_ingest" } });
    expect(ev.every((e) => e.tenantId === TENANT_A)).toBe(true);
    expect((await verifyAuditLog(TENANT_A)).valid).toBe(true);
  });

  it("refuses when the legacy bank is not active", async () => {
    await prisma.tenant.update({ where: { id: TENANT_A }, data: { active: false } });
    await expect(ingestWsusCatalog(wsusBatchSchema.parse({ updates: [{ updateId: G2, title: "x" }] }).updates)).rejects.toMatchObject({ status: 409 });
    expect(await prisma.patch.count()).toBe(0);
  });
});

describe("finding #9: discovery 'Manage' cannot add to the shared allow-list without a platform admin", () => {
  async function discovered(tenantId: string, wingetId: string) {
    return prisma.discoveredApp.create({ data: { tenantId, key: `${wingetId}|x`, displayName: "7-Zip 26.01 (x64)", publisher: "Igor Pavlov", wingetId, match: "NAME_PUBLISHER", endpointCount: 12, versions: ["26.01"] } });
  }

  it("bank admin: request only (audited on both chains); platform admin approves → shared app + bank opt-in", async () => {
    const d = await discovered(TENANT_A, "7zip.7zip");
    expect(await manageDiscovered(TENANT_A, d.id, { upn: "admin@bank-a", platformAdmin: false })).toEqual({ appId: null, requested: true });
    expect(await prisma.app.count()).toBe(0);
    expect(await prisma.tenantApp.count()).toBe(0);
    await expect(manageDiscovered(TENANT_A, d.id, { upn: "admin@bank-a", platformAdmin: false })).rejects.toMatchObject({ status: 409 });
    expect(await prisma.auditEvent.count({ where: { action: "discovery.allowlist_requested", tenantId: TENANT_A } })).toBe(1);
    expect(await prisma.auditEvent.count({ where: { action: "discovery.allowlist_requested", tenantId: null } })).toBe(1);
    // a bare UPN (legacy callers) is a bank actor too
    const d2 = await discovered(TENANT_B, "videolan.vlc");
    expect(await manageDiscovered(TENANT_B, d2.id, "admin@bank-b")).toMatchObject({ requested: true });

    const reqs = await listAllowlistRequests();
    expect(reqs.map((r) => [r.tenantId, r.wingetId, r.requestedBy])).toEqual([
      [TENANT_A, "7zip.7zip", "admin@bank-a"],
      [TENANT_B, "videolan.vlc", "admin@bank-b"],
    ]);

    const ok = await approveAllowlistRequest(d.id, "root@platform");
    expect(ok.requested).toBe(false);
    const app = await prisma.app.findUniqueOrThrow({ where: { wingetId: "7zip.7zip" } });
    expect(app).toMatchObject({ expectedPublisher: null, inventoryMatch: expect.stringMatching(/^\^7-Zip/) });
    expect(await prisma.tenantApp.findMany({ select: { tenantId: true, appId: true } })).toEqual([{ tenantId: TENANT_A, appId: app.id }]);
    expect(await prisma.auditEvent.count({ where: { action: "app.allowlist_add", tenantId: null } })).toBe(1);

    await declineAllowlistRequest(d2.id, "root@platform", "not supported");
    expect(await listAllowlistRequests()).toEqual([]);
    expect(await prisma.auditEvent.count({ where: { action: "discovery.allowlist_declined" } })).toBe(2);
    await expect(approveAllowlistRequest(d2.id, "root@platform")).rejects.toMatchObject({ status: 404 });
    for (const chain of [null, TENANT_A, TENANT_B]) expect((await verifyAuditLog(chain)).valid).toBe(true);
  });

  it("bank admin may opt in directly to an app that is already on the shared list", async () => {
    const app = await prisma.app.create({ data: { wingetId: "7zip.7zip", displayName: "7-Zip", inventoryMatch: "^7-Zip", allowedDomains: [] } });
    const d = await discovered(TENANT_B, "7zip.7zip");
    expect(await manageDiscovered(TENANT_B, d.id, { upn: "admin@bank-b", platformAdmin: false })).toEqual({ appId: app.id, requested: false });
    expect(await prisma.app.count()).toBe(1);
    expect(await prisma.auditEvent.count({ where: { action: "discovery.link", tenantId: TENANT_B } })).toBe(1);
  });
});

describe("finding #10: /repo is not public unless REPO_PUBLIC=true", () => {
  it("defaults: off in production, on in development/test; explicit value wins", () => {
    const base = { NODE_ENV: "production" as const, REPO_PUBLIC: undefined };
    expect(repoPublic({ ...base })).toBe(false);
    expect(repoPublic({ ...base, REPO_PUBLIC: "true" })).toBe(true);
    expect(repoPublic({ ...base, NODE_ENV: "development" })).toBe(true);
    expect(repoPublic({ ...base, NODE_ENV: "development", REPO_PUBLIC: "false" })).toBe(false);
  });

  it("serves 404 for every path when off, the file when on", async () => {
    mkdirSync(join(repoDir, "pkgs", "x"), { recursive: true });
    writeFileSync(join(repoDir, "pkgs", "x", "a.msi"), "bytes");
    const get = () => repoRoute.GET(new Request("http://pg.test/repo/pkgs/x/a.msi"), { params: Promise.resolve({ path: ["pkgs", "x", "a.msi"] }) } as never);
    repoPublicSwitch.value = false;
    expect((await get()).status).toBe(404);
    repoPublicSwitch.value = true;
    const on = await get();
    expect(on.status).toBe(200);
    expect(await on.text()).toBe("bytes");
  });
});

describe("finding #6: inventory regex at the API boundary", () => {
  it("rejects catastrophic patterns with a reason, accepts product-name patterns", () => {
    expect(safeRegexSchema.safeParse("^Google Chrome").success).toBe(true);
    const bad = safeRegexSchema.safeParse("^(\\w+\\s?)*$");
    expect(bad.success).toBe(false);
    expect(bad.error?.issues[0].message).toContain("unsafe or invalid regex");
    expect(safeRegexSchema.safeParse("(").success).toBe(false);
  });
});
