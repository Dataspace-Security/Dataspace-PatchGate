/**
 * Bank self-service settings through the real /api/settings routes (RLS on, TEST database only):
 * a bank admin manages only its own bank's rings / windows; a platform admin acts for the selected bank;
 * other roles get 403; deletes only of empty rings; bulk ring assignment with preview + confirm.
 * Run: TEST_DATABASE_URL=postgresql://…/patchgate_test_auth INTEGRATION=1 npx vitest run src/test/settings.int.test.ts
 */
import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";
import { TENANT_A, TENANT_B, asSessionUser, configureTestEnv, resetDb } from "./helpers";

type TestUser = { id: string; role: "VIEWER" | "OPERATOR" | "APPROVER" | "ADMIN"; upn: string; name: string; tenantId: string | null };

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

configureTestEnv();
vi.setConfig({ testTimeout: 300_000, hookTimeout: 120_000 });

const { prisma } = await import("@/lib/db");
const { withTenant } = await import("@/lib/tenancy");
const ringsRoute = await import("@/app/api/settings/rings/route");
const ringRoute = await import("@/app/api/settings/rings/[id]/route");
const orderRoute = await import("@/app/api/settings/rings/order/route");
const bulkRoute = await import("@/app/api/settings/rings/bulk-assign/route");
const windowsRoute = await import("@/app/api/settings/windows/route");
const windowRoute = await import("@/app/api/settings/windows/[id]/route");
const previewRoute = await import("@/app/api/settings/windows/preview/route");
const approvalsRoute = await import("@/app/api/settings/approvals/route");

const ORIGIN = "http://patchgate.test";
function req(method: string, path: string, body?: unknown): Request {
  return new Request(`${ORIGIN}${path}`, {
    method,
    headers: { origin: ORIGIN, "x-forwarded-host": "patchgate.test", "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}
const params = (id: string) => ({ params: Promise.resolve({ id }) });
async function json<T = unknown>(res: Response): Promise<{ success: boolean; data: T; error: string | null; status: number }> {
  return { ...((await res.json()) as { success: boolean; data: T; error: string | null }), status: res.status };
}

async function seed() {
  const mk = (upn: string, role: TestUser["role"], tenantId: string | null) => prisma.user.create({ data: { upn, name: upn, role, tenantId } }).then(asSessionUser);
  const users = {
    platformAdmin: await mk("admin@pg", "ADMIN", null),
    platformOperator: await mk("operator@pg", "OPERATOR", null),
    adminA: await mk("admin@a", "ADMIN", TENANT_A),
    adminB: await mk("admin@b", "ADMIN", TENANT_B),
    approverA: await mk("approver@a", "APPROVER", TENANT_A),
  };
  const ringA = await withTenant(TENANT_A, async (tx) => {
    const r = await tx.ring.create({ data: { tenantId: TENANT_A, name: "Ring0-Test", wsusGroup: "Ring0-Test", order: 0 } });
    const hosts = ["BR-PUNE-001", "BR-PUNE-002", "BR-MUM-001", "HQ-001"];
    for (const [i, h] of hosts.entries()) {
      await tx.endpoint.create({ data: { tenantId: TENANT_A, tacticalAgentId: `a-${i}`, hostname: h, site: h.startsWith("BR-PUNE") ? "Pune" : h.startsWith("BR-MUM") ? "Mumbai" : "HQ" } });
    }
    return r;
  });
  const ringB = await withTenant(TENANT_B, (tx) => tx.ring.create({ data: { tenantId: TENANT_B, name: "Ring0-Test", wsusGroup: "Ring0-Test", order: 0 } }));
  return { users, ringA, ringB };
}

const as = (u: TestUser, cookie?: string) => {
  ctx.user = u;
  ctx.tenantCookie = cookie;
};

beforeEach(async () => {
  await prisma.$executeRawUnsafe(`DELETE FROM "ChangeRequestApproval"`);
  await resetDb(prisma);
  ctx.user = null;
  ctx.tenantCookie = undefined;
});
afterAll(() => prisma.$disconnect());

describe("settings access", () => {
  it("a bank admin manages only its own bank's rings (cookie ignored); another bank's ring is a 404", async () => {
    const { users, ringA, ringB } = await seed();
    as(users.adminB, TENANT_A); // a bank user cannot switch banks with the cookie
    const list = await json<{ id: string }[]>(await ringsRoute.GET(req("GET", "/api/settings/rings")));
    expect(list.data.map((r) => r.id)).toEqual([ringB.id]);
    const r1 = await json(await ringRoute.PATCH(req("PATCH", `/api/settings/rings/${ringA.id}`, { name: "Hacked" }), params(ringA.id)));
    expect(r1.status).toBe(404);
    const r2 = await json(await ringRoute.DELETE(req("DELETE", `/api/settings/rings/${ringA.id}`), params(ringA.id)));
    expect(r2.status).toBe(404);
    const w = await json(await windowsRoute.POST(req("POST", "/api/settings/windows", { name: "Sneaky", ringId: ringA.id, cron: "0 2 * * 0", durationMin: 60, timezone: "UTC" })));
    expect(w.status).toBe(404);
    expect((await prisma.ring.findUniqueOrThrow({ where: { id: ringA.id } })).name).toBe("Ring0-Test");
  });

  it("platform admin acts for the selected bank; operators/approvers are refused; no bank selected = 409", async () => {
    const { users, ringA } = await seed();
    as(users.platformAdmin);
    expect((await ringsRoute.GET(req("GET", "/api/settings/rings"))).status).toBe(409);
    as(users.platformAdmin, TENANT_A);
    const ok = await json(await ringRoute.PATCH(req("PATCH", `/api/settings/rings/${ringA.id}`, { name: "Ring0-Lab" }), params(ringA.id)));
    expect(ok.success).toBe(true);
    // wsusGroup followed the name (it was the default)
    expect(await prisma.ring.findUniqueOrThrow({ where: { id: ringA.id } })).toMatchObject({ name: "Ring0-Lab", wsusGroup: "Ring0-Lab" });
    for (const u of [users.platformOperator, users.approverA]) {
      as(u, TENANT_A);
      expect((await ringsRoute.POST(req("POST", "/api/settings/rings", { name: "X-ring" }))).status).toBe(403);
    }
    const cross = await fetchCrossSite(users.adminA);
    expect(cross.status).toBe(403);
  });
});

async function fetchCrossSite(u: TestUser): Promise<Response> {
  as(u);
  return ringsRoute.POST(new Request(`${ORIGIN}/api/settings/rings`, { method: "POST", headers: { origin: "https://evil.test", host: "patchgate.test" }, body: "{}" }));
}

describe("rings", () => {
  it("create, reorder (two-phase on the unique order), delete only when empty; all audited on the bank chain", async () => {
    const { users, ringA } = await seed();
    as(users.adminA);
    const created = await json<{ id: string; order: number; wsusGroup: string }>(await ringsRoute.POST(req("POST", "/api/settings/rings", { name: "Ring1-Pilot", rebootPolicy: "NEVER" })));
    expect(created.data).toMatchObject({ order: 1, wsusGroup: "Ring1-Pilot" });
    const dup = await json(await ringsRoute.POST(req("POST", "/api/settings/rings", { name: "Ring1-Pilot" })));
    expect(dup.status).toBe(409);

    const bad = await json(await orderRoute.PUT(req("PUT", "/api/settings/rings/order", { ringIds: [created.data.id] })));
    expect(bad.status).toBe(400);
    expect((await orderRoute.PUT(req("PUT", "/api/settings/rings/order", { ringIds: [created.data.id, ringA.id] }))).status).toBe(200);
    const rings = await withTenant(TENANT_A, (tx) => tx.ring.findMany({ where: { tenantId: TENANT_A }, orderBy: { order: "asc" } }));
    expect(rings.map((r) => r.name)).toEqual(["Ring1-Pilot", "Ring0-Test"]);

    // Ring with endpoints cannot be deleted; empty ring (+ its windows) can
    await withTenant(TENANT_A, (tx) => tx.endpoint.updateMany({ where: { tenantId: TENANT_A, hostname: "HQ-001" }, data: { ringId: ringA.id } }));
    expect((await ringRoute.DELETE(req("DELETE", `/api/settings/rings/${ringA.id}`), params(ringA.id))).status).toBe(409);
    await windowsRoute.POST(req("POST", "/api/settings/windows", { name: "Pilot window", ringId: created.data.id, cron: "0 1 * * 6", durationMin: 90, timezone: "Asia/Kolkata" }));
    expect((await ringRoute.DELETE(req("DELETE", `/api/settings/rings/${created.data.id}`), params(created.data.id))).status).toBe(200);
    expect(await withTenant(TENANT_A, (tx) => tx.maintenanceWindow.count({ where: { tenantId: TENANT_A } }))).toBe(0);

    const audit = await withTenant(TENANT_A, (tx) => tx.auditEvent.findMany({ where: { tenantId: TENANT_A }, select: { action: true } }));
    expect(audit.map((a) => a.action)).toEqual(expect.arrayContaining(["ring.created", "ring.reordered", "window.created", "ring.deleted"]));
  });

  it("bulk-assigns by site / hostname pattern: preview count, confirm, refuse a stale count", async () => {
    const { users, ringA } = await seed();
    as(users.adminA);
    const filter = { hostnamePattern: "br-pune-*" };
    const prev = await json<{ count: number; sample: string[] }>(await bulkRoute.POST(req("POST", "/api/settings/rings/bulk-assign", { mode: "preview", filter })));
    expect(prev.data).toEqual({ count: 2, sample: ["BR-PUNE-001", "BR-PUNE-002"] });
    const stale = await json(await bulkRoute.POST(req("POST", "/api/settings/rings/bulk-assign", { mode: "confirm", filter, ringId: ringA.id, expectedCount: 3 })));
    expect(stale.status).toBe(409);
    const done = await json<{ moved: number }>(await bulkRoute.POST(req("POST", "/api/settings/rings/bulk-assign", { mode: "confirm", filter, ringId: ringA.id, expectedCount: 2 })));
    expect(done.data.moved).toBe(2);
    const bySite = await json<{ count: number }>(await bulkRoute.POST(req("POST", "/api/settings/rings/bulk-assign", { mode: "preview", filter: { site: "Mumbai" } })));
    expect(bySite.data.count).toBe(1);
    expect(await withTenant(TENANT_A, (tx) => tx.endpoint.count({ where: { tenantId: TENANT_A, ringId: ringA.id } }))).toBe(2);
    const ev = await withTenant(TENANT_A, (tx) => tx.auditEvent.findFirstOrThrow({ where: { tenantId: TENANT_A, action: "endpoint.bulk_assign_ring" } }));
    expect(ev.payload).toMatchObject({ matched: 2, moved: 2 });
    // Another bank's admin sees none of bank A's PCs
    as(users.adminB);
    const other = await json<{ count: number }>(await bulkRoute.POST(req("POST", "/api/settings/rings/bulk-assign", { mode: "preview", filter })));
    expect(other.data.count).toBe(0);
  });
});

describe("maintenance windows", () => {
  it("validates cron, previews the next 5 occurrences in the bank timezone, locks the schedule of a window in use", async () => {
    const { users, ringA } = await seed();
    as(users.adminA);
    const badCron = await json(await previewRoute.POST(req("POST", "/api/settings/windows/preview", { cron: "0 25 * * *", durationMin: 60, timezone: "UTC" })));
    expect(badCron.status).toBe(400);
    const prev = await json<{ bankTimezone: string; occurrences: { startLocal: string }[] }>(
      await previewRoute.POST(req("POST", "/api/settings/windows/preview", { cron: "0 2 * * 0", durationMin: 120, timezone: "Asia/Kolkata" })),
    );
    expect(prev.data.bankTimezone).toBe("Asia/Kolkata");
    expect(prev.data.occurrences).toHaveLength(5);
    expect(prev.data.occurrences[0]!.startLocal).toMatch(/Sun.*02:00/);

    const created = await json<{ id: string }>(await windowsRoute.POST(req("POST", "/api/settings/windows", { name: "Sunday", ringId: ringA.id, cron: "0 2 * * 0", durationMin: 120, timezone: "Asia/Kolkata" })));
    expect(created.status).toBe(201);
    const overlap = await json(await windowsRoute.POST(req("POST", "/api/settings/windows", { name: "Hourly", ringId: ringA.id, cron: "0 * * * *", durationMin: 120, timezone: "UTC" })));
    expect(overlap.status).toBe(400);

    // A pending change request uses the window → schedule locked, delete refused
    const maker = await prisma.user.create({ data: { upn: "maker@pg", name: "m", role: "OPERATOR" } });
    await withTenant(TENANT_A, (tx) =>
      tx.changeRequest.create({ data: { tenantId: TENANT_A, title: "uses window", ringId: ringA.id, windowId: created.data.id, createdById: maker.id, status: "PENDING_APPROVAL" } }),
    );
    const id = created.data.id;
    const locked = await json(await windowRoute.PATCH(req("PATCH", `/api/settings/windows/${id}`, { name: "Sunday", ringId: ringA.id, cron: "0 3 * * 0", durationMin: 120, timezone: "Asia/Kolkata" }), params(id)));
    expect(locked.status).toBe(409);
    const rename = await json(await windowRoute.PATCH(req("PATCH", `/api/settings/windows/${id}`, { name: "Sunday early", ringId: ringA.id, cron: "0 2 * * 0", durationMin: 120, timezone: "Asia/Kolkata" }), params(id)));
    expect(rename.success).toBe(true);
    expect((await windowRoute.DELETE(req("DELETE", `/api/settings/windows/${id}`), params(id))).status).toBe(409);

    as(users.adminB);
    expect((await windowRoute.DELETE(req("DELETE", `/api/settings/windows/${id}`), params(id))).status).toBe(404);
  });
});

describe("approval policy route", () => {
  it("reads and updates the active bank's policy", async () => {
    const { users } = await seed();
    as(users.adminA);
    const got = await json<{ approvalExpiryDays: number }>(await approvalsRoute.GET(req("GET", "/api/settings/approvals")));
    expect(got.data.approvalExpiryDays).toBe(14);
    const upd = await json(await approvalsRoute.PATCH(req("PATCH", "/api/settings/approvals", { approvalExpiryDays: 3, timezone: "Europe/London" })));
    expect(upd.success).toBe(true);
    const bad = await json(await approvalsRoute.PATCH(req("PATCH", "/api/settings/approvals", { timezone: "Nowhere/Land" })));
    expect(bad.status).toBe(400);
    expect(await prisma.tenant.findUniqueOrThrow({ where: { id: TENANT_A } })).toMatchObject({ approvalExpiryDays: 3, timezone: "Europe/London" });
    expect((await prisma.tenant.findUniqueOrThrow({ where: { id: TENANT_B } })).approvalExpiryDays).toBe(14);
  });
});
