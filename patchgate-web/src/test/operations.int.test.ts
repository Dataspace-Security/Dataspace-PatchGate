/**
 * /operations view model: platform staff only (bank users get 403 before any data is read), one aggregated
 * row per bank, worst first, paged — as the NON-owner, NOBYPASSRLS runtime role.
 */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { TENANT_A, TENANT_B, asSessionUser, configureTestEnv, resetDb } from "./helpers";

const APP_ROLE = "patchgate_app_test";
const APP_PASSWORD = "app-role-test-only-0123456789";
const repoDir = mkdtempSync(join(tmpdir(), "pg-ops-"));

configureTestEnv({ REPO_DIR: repoDir });
const adminUrl = process.env.DATABASE_URL!;
const { PrismaClient } = await import("@prisma/client");
const admin = new PrismaClient({ datasourceUrl: adminUrl });

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
const { AuthError } = await import("@/lib/auth/session");
const { OPS_PAGE_SIZE, loadOperations } = await import("@/lib/metrics/operations");
const { resetOpsSnapshotCache } = await import("@/lib/metrics/collect");

const HOUR = 3_600_000;
const ago = (ms: number) => new Date(Date.now() - ms);
const EXTRA_BANKS = 28; // 30 banks in total → 2 pages

const platformViewer = asSessionUser({ id: "u-pv", role: "AUDITOR", upn: "viewer@patchgate.test", name: "Platform Viewer", tenantId: null });
const bankAdmin = asSessionUser({ id: "u-ba", role: "ADMIN", upn: "admin@bank-a.test", name: "Bank Admin", tenantId: TENANT_A });

beforeAll(async () => {
  await resetDb(admin);
  // Bank A: one site connector offline for 2 h → red. Bank B: healthy connector.
  await admin.connector.create({ data: { tenantId: TENANT_A, name: "HQ", publicKey: "k1", version: "1.4.0", lastSeenAt: ago(2 * HOUR) } });
  await admin.connector.create({ data: { tenantId: TENANT_B, name: "B-HQ", publicKey: "k2", version: "1.4.0", lastSeenAt: ago(30_000) } });
  await admin.tenant.createMany({
    data: Array.from({ length: EXTRA_BANKS }, (_, i) => ({ id: `tenant-ops-${i}`, slug: `ops-${String(i).padStart(2, "0")}`, name: `Ops Bank ${String(i).padStart(2, "0")}` })),
  });
  resetOpsSnapshotCache();
}, 120_000);

afterAll(async () => {
  await admin.$disconnect();
  await prisma.$disconnect();
  rmSync(repoDir, { recursive: true, force: true });
});

describe("/operations access", () => {
  it("bank users (even admins) get 403", async () => {
    const err = await loadOperations(bankAdmin).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AuthError);
    expect(err).toMatchObject({ status: 403 });
  });

  it("platform staff of any role see every bank", async () => {
    const view = await loadOperations(platformViewer);
    expect(view.totalBanks).toBe(2 + EXTRA_BANKS);
    expect(view.rows).toHaveLength(OPS_PAGE_SIZE);
    expect(view.pages).toBe(2);
  });
});

describe("/operations rows", () => {
  it("lists the worst bank first with aggregated connector figures", async () => {
    const view = await loadOperations(platformViewer);
    const first = view.rows[0];
    expect(first.bank.tenantId).toBe(TENANT_A);
    expect(first.rag.connectors).toBe("red");
    expect(first.rag.overall).toBe("red");
    expect(first.offline).toBe(1);
    expect(first.worstLastSeenAgeSec).toBeGreaterThan(7000);
    const b = view.rows.find((r) => r.bank.tenantId === TENANT_B)!;
    expect(b.online).toBe(1);
    expect(b.rag.connectors).toBe("green");
  });

  it("filters to banks that need attention", async () => {
    const view = await loadOperations(platformViewer, { filter: "issues" });
    expect(view.rows.map((r) => r.bank.tenantId)).toEqual([TENANT_A]);
    expect(view.banksWithIssues).toBe(1);
    expect(view.pages).toBe(1);
  });

  it("pages and clamps out-of-range pages", async () => {
    const p2 = await loadOperations(platformViewer, { page: 2 });
    expect(p2.page).toBe(2);
    expect(p2.rows).toHaveLength(2 + EXTRA_BANKS - OPS_PAGE_SIZE);
    const p9 = await loadOperations(platformViewer, { page: 9 });
    expect(p9.page).toBe(2);
    const page1Ids = new Set((await loadOperations(platformViewer)).rows.map((r) => r.bank.tenantId));
    expect(p2.rows.some((r) => page1Ids.has(r.bank.tenantId))).toBe(false);
  });
});
