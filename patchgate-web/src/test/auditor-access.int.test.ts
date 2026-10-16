/**
 * Role model (ADMIN / AUDITOR in every scope) against a real PostgreSQL (TEST database only):
 *  1. the data migration 20261016140100_role_scope maps the retired roles without ever escalating across
 *     scopes, and the User_role_scope CHECK refuses them afterwards;
 *  2. a platform AUDITOR reads every list a platform admin sees (all banks), a bank AUDITOR its own bank;
 *  3. auditors never receive one-time secrets (temporary passwords, enrolment codes, clear webhook URLs);
 *  4. the normal flow: platform admin raises → bank admin approves; a bank auditor cannot decide.
 * (403 on EVERY mutating route: src/app/api/auditor-write-matrix.test.ts.)
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";
import { TENANT_A, TENANT_B, asSessionUser, configureTestEnv, resetDb } from "./helpers";

type TestUser = { id: string; role: import("@/lib/auth/roles").Role; upn: string; name: string; tenantId: string | null };
const HOOK_HOST = "hooks.test.example";
const ctx = vi.hoisted(() => ({ user: null as TestUser | null, tenantCookie: undefined as string | undefined }));

vi.mock("next/headers", () => ({
  cookies: async () => ({
    get: (name: string) => (name === "pg_tenant" && ctx.tenantCookie ? { name, value: ctx.tenantCookie } : undefined),
    set: () => undefined,
    delete: () => undefined,
  }),
}));

vi.mock("@/lib/auth/session", async (importOriginal) => {
  const orig = await importOriginal<typeof import("@/lib/auth/session")>();
  return {
    ...orig,
    getCurrentUser: async () => {
      if (!ctx.user) throw new orig.AuthError("Not signed in", 401);
      return ctx.user;
    },
  };
});

configureTestEnv({ PUBLIC_BASE_URL: "https://patchgate.test.local", NOTIFY_WEBHOOK_ALLOWED_HOSTS: HOOK_HOST });
vi.setConfig({ testTimeout: 300_000, hookTimeout: 120_000 });

const { prisma } = await import("@/lib/db");
const { withTenant } = await import("@/lib/tenancy");
const { createChangeRequest, applyAction } = await import("@/lib/approvals/service");
const { updateNotificationSettings } = await import("@/lib/notify/settings");
const routes = {
  users: await import("@/app/api/admin/users/route"),
  userAction: await import("@/app/api/admin/users/[id]/[action]/route"),
  tenants: await import("@/app/api/admin/tenants/route"),
  auditVerify: await import("@/app/api/audit/verify/route"),
  notifySettings: await import("@/app/api/notifications/settings/route"),
  outbox: await import("@/app/api/notifications/outbox/route"),
  rings: await import("@/app/api/settings/rings/route"),
  windows: await import("@/app/api/settings/windows/route"),
  approvals: await import("@/app/api/settings/approvals/route"),
  security: await import("@/app/api/settings/security/route"),
  crs: await import("@/app/api/change-requests/route"),
  crAction: await import("@/app/api/change-requests/[id]/[action]/route"),
  patches: await import("@/app/api/patches/route"),
  enrollments: await import("@/app/api/connector/admin/enrollments/route"),
  reportsCsv: await import("@/app/api/reports/csv/route"),
};

const ORIGIN = "http://patchgate.test";
function req(method: string, path: string, body?: unknown): Request {
  return new Request(`${ORIGIN}${path}`, {
    method,
    headers: { origin: ORIGIN, "x-forwarded-host": "patchgate.test", "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}
const params = <T extends Record<string, string>>(p: T) => ({ params: Promise.resolve(p) });
async function body(res: Response): Promise<{ status: number; success: boolean; data: unknown; text: string }> {
  const text = await res.text();
  const j = (() => {
    try {
      return JSON.parse(text) as { success: boolean; data: unknown };
    } catch {
      return { success: res.ok, data: null };
    }
  })();
  return { status: res.status, success: j.success, data: j.data, text };
}

async function seed() {
  const mk = (upn: string, role: TestUser["role"], tenantId: string | null) => prisma.user.create({ data: { upn, name: upn, role, tenantId } }).then(asSessionUser);
  const users = {
    platformAdmin: await mk("admin@pg.test", "ADMIN", null),
    platformAuditor: await mk("auditor@pg.test", "AUDITOR", null),
    adminA: await mk("admin@a.test", "ADMIN", TENANT_A),
    auditorA: await mk("auditor@a.test", "AUDITOR", TENANT_A),
    adminB: await mk("admin@b.test", "ADMIN", TENANT_B),
  };
  const patch = await prisma.patch.create({ data: { kind: "WINDOWS", externalId: "33333333-3333-3333-3333-333333333333", kb: "KB5000001", title: "KB5000001", severity: "CRITICAL" } });
  const ring = await prisma.ring.create({ data: { tenantId: TENANT_A, name: "Ring0-Test", wsusGroup: "Ring0-Test", order: 0 } });
  const endpoint = await prisma.endpoint.create({ data: { tenantId: TENANT_A, tacticalAgentId: "agentAUD000001", hostname: "A-PC1", ringId: ring.id } });
  await prisma.endpointPatchState.create({ data: { tenantId: TENANT_A, endpointId: endpoint.id, patchId: patch.id, status: "NEEDED" } });
  return { users, ring, patch };
}

beforeEach(async () => {
  await resetDb(prisma);
  ctx.user = null;
  ctx.tenantCookie = undefined;
});
afterAll(() => prisma.$disconnect());

describe("data migration 20261016140100_role_scope", () => {
  const sql = readFileSync(fileURLToPath(new URL("../../prisma/migrations/20261016140100_role_scope/migration.sql", import.meta.url)), "utf8");
  const statements = sql
    .split("\n")
    .filter((l) => !l.trim().startsWith("--"))
    .join("\n")
    .split(";")
    .map((s) => s.trim())
    .filter(Boolean);

  it("maps the retired roles (never escalating across scopes) and the CHECK refuses them afterwards", async () => {
    class Rollback extends Error {}
    let mapped: Record<string, string> = {};
    await prisma
      .$transaction(async (tx) => {
        // Recreate the pre-migration state inside this transaction only (DDL is transactional in PostgreSQL).
        await tx.$executeRawUnsafe(`ALTER TABLE "User" DROP CONSTRAINT "User_role_scope"`);
        const rows: [string, string, string | null][] = [
          ["p-op", "OPERATOR", null],
          ["p-appr", "APPROVER", null],
          ["p-view", "VIEWER", null],
          ["p-admin", "ADMIN", null],
          ["b-op", "OPERATOR", TENANT_A],
          ["b-appr", "APPROVER", TENANT_A],
          ["b-view", "VIEWER", TENANT_A],
          ["b-admin", "ADMIN", TENANT_B],
        ];
        for (const [id, role, tenantId] of rows) {
          await tx.$executeRawUnsafe(`INSERT INTO "User" ("id", "upn", "name", "role", "tenantId") VALUES ($1, $2, $1, $3::"UserRole", $4)`, id, `${id}@m.test`, role, tenantId);
        }
        for (const s of statements) await tx.$executeRawUnsafe(s);
        const after = await tx.$queryRawUnsafe<{ id: string; role: string }[]>(`SELECT "id", "role"::text AS role FROM "User" WHERE "upn" LIKE '%@m.test'`);
        mapped = Object.fromEntries(after.map((r) => [r.id, r.role]));
        await expect(tx.$executeRawUnsafe(`UPDATE "User" SET "role" = 'APPROVER' WHERE "id" = 'b-admin'`)).rejects.toThrow(/User_role_scope/);
        throw new Rollback();
      }, { timeout: 60_000 })
      .catch((err: unknown) => {
        if (!(err instanceof Rollback)) throw err;
      });
    expect(mapped).toEqual({
      "p-op": "AUDITOR",
      "p-appr": "AUDITOR",
      "p-view": "AUDITOR",
      "p-admin": "ADMIN",
      "b-op": "AUDITOR",
      "b-appr": "ADMIN", // bank approvers become bank admins: the bank's checkers
      "b-view": "AUDITOR",
      "b-admin": "ADMIN",
    });
    // rolled back: the live constraint is still there
    await expect(prisma.user.create({ data: { upn: "x@m.test", name: "x", role: "VIEWER" } })).rejects.toThrow(/User_role_scope/);
  });
});

describe("AUDITOR reads, never writes, never sees one-time secrets", () => {
  it("platform auditor: every platform list (all banks) + the selected bank's pages", async () => {
    const { users } = await seed();
    ctx.user = users.platformAuditor;
    const allUsers = await body(await routes.users.GET());
    expect(allUsers.status).toBe(200);
    expect((allUsers.data as { upn: string }[]).map((u) => u.upn)).toEqual(expect.arrayContaining(["admin@a.test", "admin@b.test", "admin@pg.test"]));
    expect(allUsers.text).not.toMatch(/passwordHash|totpSecret|temporaryPassword/);
    expect((await body(await routes.tenants.GET())).data).toHaveLength(2);
    expect((await body(await routes.auditVerify.GET(req("GET", "/api/audit/verify?chain=platform")))).status).toBe(200);
    expect((await body(await routes.outbox.GET(req("GET", "/api/notifications/outbox")))).status).toBe(200);
    expect((await body(await routes.notifySettings.GET(req("GET", "/api/notifications/settings?scope=platform")))).status).toBe(200);
    expect((await body(await routes.security.GET())).status).toBe(200);
    ctx.tenantCookie = TENANT_B;
    for (const r of [routes.rings, routes.windows, routes.approvals]) {
      expect((await body(await r.GET(req("GET", "/api/settings/x")))).status).toBe(200);
    }
    expect((await body(await routes.crs.GET())).status).toBe(200);
    expect((await body(await routes.patches.GET(req("GET", "/api/patches")))).status).toBe(200);
    expect((await routes.reportsCsv.GET(req("GET", "/api/reports/csv?section=summary"))).status).toBe(200);
  });

  it("bank auditor: its own bank only", async () => {
    const { users } = await seed();
    ctx.user = users.auditorA;
    const list = (await body(await routes.users.GET())).data as { upn: string; tenantId: string | null }[];
    expect(list.every((u) => u.tenantId === TENANT_A)).toBe(true);
    expect(list.map((u) => u.upn).sort()).toEqual(["admin@a.test", "auditor@a.test"]);
    expect((await body(await routes.rings.GET(req("GET", "/api/settings/rings")))).status).toBe(200);
    expect((await body(await routes.outbox.GET(req("GET", "/api/notifications/outbox")))).status).toBe(403); // platform-only
    expect((await body(await routes.security.GET())).status).toBe(403);
  });

  it("gets 403 — and no secret — when trying to create users, reset passwords or enrol connectors", async () => {
    const { users } = await seed();
    for (const auditor of [users.platformAuditor, users.auditorA]) {
      ctx.user = auditor;
      const created = await body(await routes.users.POST(req("POST", "/api/admin/users", { upn: "new@a.test", name: "New", role: "ADMIN", tenantId: TENANT_A })));
      expect(created.status).toBe(403);
      expect(created.text).not.toMatch(/temporaryPassword/);
      const reset = await body(await routes.userAction.POST(req("POST", `/api/admin/users/${users.adminA.id}/reset-password`), params({ id: users.adminA.id, action: "reset-password" })));
      expect(reset.status).toBe(403);
      expect(reset.text).not.toMatch(/temporaryPassword/);
      const code = await body(await routes.enrollments.POST(req("POST", "/api/connector/admin/enrollments", { tenantId: TENANT_A, name: "site-1" })));
      expect(code.status).toBe(403);
      expect(code.text).not.toMatch(/"code"/);
    }
    expect(await prisma.user.count({ where: { upn: "new@a.test" } })).toBe(0);
    expect(await prisma.connectorEnrollment.count()).toBe(0);
  });

  it("sees webhook URLs masked only (the secret token in the path never leaves the server)", async () => {
    const { users } = await seed();
    const url = `https://${HOOK_HOST}/webhookb2/SECRET-TOKEN-0123456789abcdef/IncomingWebhook/xyz9`;
    await updateNotificationSettings(users.adminA, TENANT_A, { action: "add-webhook", url });
    for (const auditor of [users.platformAuditor, users.auditorA]) {
      ctx.user = auditor;
      const r = await body(await routes.notifySettings.GET(req("GET", `/api/notifications/settings?scope=${TENANT_A}`)));
      expect(r.status).toBe(200);
      expect(r.text).not.toContain("SECRET-TOKEN");
      expect((r.data as { webhooks: { display: string }[] }).webhooks[0]?.display).toBe(`https://${HOOK_HOST}/…xyz9`);
      const post = await body(await routes.notifySettings.POST(req("POST", "/api/notifications/settings", { scope: TENANT_A, action: "set-events", disabledEvents: [] })));
      expect(post.status).toBe(403);
    }
  });

  it("normal flow: platform admin raises → bank admin approves; auditors cannot raise or decide", async () => {
    const { users, ring, patch } = await seed();
    ctx.tenantCookie = TENANT_A;
    ctx.user = users.platformAuditor;
    expect((await body(await routes.crs.POST(req("POST", "/api/change-requests", { title: "October", ringId: ring.id, patchIds: [patch.id] })))).status).toBe(403);

    const cr = await createChangeRequest(users.platformAdmin, TENANT_A, { title: "October", ringId: ring.id, patchIds: [patch.id] });
    await applyAction(users.platformAdmin, TENANT_A, cr.id, "submit");
    ctx.user = users.auditorA;
    expect((await body(await routes.crAction.POST(req("POST", `/api/change-requests/${cr.id}/approve`, {}), params({ id: cr.id, action: "approve" })))).status).toBe(403);
    ctx.user = users.adminA;
    const ok = await body(await routes.crAction.POST(req("POST", `/api/change-requests/${cr.id}/approve`, {}), params({ id: cr.id, action: "approve" })));
    expect(ok.status).toBe(200);
    const after = await withTenant(TENANT_A, (tx) => tx.changeRequest.findUniqueOrThrow({ where: { id: cr.id } }));
    expect(after.status).toBe("APPROVED");
    expect(after.approvedById).toBe(users.adminA.id);
  });
});
