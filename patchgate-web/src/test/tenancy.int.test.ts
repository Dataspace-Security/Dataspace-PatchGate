/**
 * Multi-bank isolation against a real PostgreSQL (TEST database only):
 *  1. Row-Level Security: inside withTenant(A) bank B's rows are invisible and cannot be written.
 *  2. API level: a bank B user cannot read or act on bank A objects (404/403), platform staff must pick
 *     a bank, bank users can never switch, trust decisions are platform-admin only.
 *  3. Per-bank maker-checker policy end to end.
 */
import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";
import { TENANT_A, TENANT_B, asSessionUser, configureTestEnv, resetDb } from "./helpers";

type TestUser = { id: string; role: "VIEWER" | "OPERATOR" | "APPROVER" | "ADMIN"; upn: string; name: string; tenantId: string | null };

// Request context stand-ins: the signed-in user and the browser's pg_tenant cookie.
const ctx = vi.hoisted(() => ({
  user: null as TestUser | null,
  tenantCookie: undefined as string | undefined,
  setCookies: [] as [string, string][],
}));

vi.mock("next/headers", () => ({
  cookies: async () => ({
    get: (name: string) => (name === "pg_tenant" && ctx.tenantCookie ? { name, value: ctx.tenantCookie } : undefined),
    set: (name: string, value: string) => {
      ctx.setCookies.push([name, value]);
    },
    delete: (name: string) => {
      ctx.setCookies.push([name, ""]);
    },
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
const { prisma } = await import("@/lib/db");
const { withTenant, withPlatform } = await import("@/lib/tenancy");
const { appendAudit } = await import("@/lib/audit/service");
const { createChangeRequest, applyAction } = await import("@/lib/approvals/service");
const crCollection = await import("@/app/api/change-requests/route");
const crAction = await import("@/app/api/change-requests/[id]/[action]/route");
const endpointRoute = await import("@/app/api/endpoints/[id]/route");
const discoveryRoute = await import("@/app/api/discovery/[id]/[action]/route");
const tenantSelect = await import("@/app/api/tenant/select/route");
const packageDecision = await import("@/app/api/packages/[id]/[decision]/route");
const appToggle = await import("@/app/api/apps/[id]/[action]/route");
const patchesRoute = await import("@/app/api/patches/route");

const ORIGIN = "http://patchgate.test";

function req(method: string, path: string, body?: unknown): Request {
  return new Request(`${ORIGIN}${path}`, {
    method,
    headers: { origin: ORIGIN, "x-forwarded-host": "patchgate.test", "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}
const params = <T extends Record<string, string>>(p: T) => ({ params: Promise.resolve(p) });

async function json(res: Response): Promise<{ success: boolean; data: unknown; error: string | null }> {
  return (await res.json()) as { success: boolean; data: unknown; error: string | null };
}

/** Two banks, each with a ring, an endpoint, a discovered product and a pending change request. */
async function seed() {
  const mk = (upn: string, role: TestUser["role"], tenantId: string | null) =>
    prisma.user.create({ data: { upn, name: upn, role, tenantId } }).then(asSessionUser);
  const users = {
    platformOperator: await mk("operator@pg", "OPERATOR", null),
    platformAdmin: await mk("admin@pg", "ADMIN", null),
    approverA: await mk("approver@a", "APPROVER", TENANT_A),
    approverB: await mk("approver@b", "APPROVER", TENANT_B),
    adminB: await mk("admin@b", "ADMIN", TENANT_B),
  };
  const patch = await prisma.patch.create({
    data: { kind: "WINDOWS", externalId: "22222222-2222-2222-2222-222222222222", kb: "KB2", title: "KB2", severity: "CRITICAL" },
  });
  const bank = async (tenantId: string, tag: string) => {
    const ring = await prisma.ring.create({ data: { tenantId, name: "Ring0", wsusGroup: "Ring0", order: 0 } });
    const endpoint = await prisma.endpoint.create({ data: { tenantId, tacticalAgentId: `agent${tag}000001`, hostname: `${tag}-PC1`, ringId: ring.id } });
    await prisma.endpointPatchState.create({ data: { tenantId, endpointId: endpoint.id, patchId: patch.id, status: "NEEDED" } });
    const discovered = await prisma.discoveredApp.create({ data: { tenantId, key: `git|${tag}`, displayName: "Git", wingetId: "Git.Git", versions: [] } });
    const cr = await createChangeRequest(users.platformOperator, tenantId, { title: `CR ${tag}`, ringId: ring.id, patchIds: [patch.id] });
    await applyAction(users.platformOperator, tenantId, cr.id, "submit");
    return { ring, endpoint, discovered, cr };
  };
  return { users, patch, a: await bank(TENANT_A, "A"), b: await bank(TENANT_B, "B") };
}

beforeEach(async () => {
  await resetDb(prisma);
  ctx.user = null;
  ctx.tenantCookie = undefined;
  ctx.setCookies = [];
});
afterAll(() => prisma.$disconnect());

describe("PostgreSQL Row-Level Security", () => {
  it("withTenant(A) runs as the RLS role and sees only bank A's rows", async () => {
    const { a } = await seed();
    const seen = await withTenant(TENANT_A, async (tx) => ({
      role: (await tx.$queryRaw<{ r: string }[]>`SELECT current_user AS r`)[0].r,
      rings: await tx.ring.findMany({ select: { tenantId: true } }),
      endpoints: await tx.endpoint.count(),
      states: await tx.endpointPatchState.count(),
      crs: await tx.changeRequest.findMany({ select: { id: true } }),
      crPatches: await tx.changeRequestPatch.count(),
      discovered: await tx.discoveredApp.count(),
      deployments: await tx.deployment.count(),
      audit: await tx.auditEvent.findMany({ select: { tenantId: true } }),
      // raw SQL is filtered too: the policy applies below the ORM
      rawEndpoints: (await tx.$queryRaw<{ n: bigint }[]>`SELECT COUNT(*) AS n FROM "Endpoint"`)[0].n,
    }));
    expect(seen.role).toBe("patchgate_tenant");
    expect(seen.rings).toEqual([{ tenantId: TENANT_A }]);
    expect(seen).toMatchObject({ endpoints: 1, states: 1, crPatches: 1, discovered: 1, deployments: 0, rawEndpoints: BigInt(1) });
    expect(seen.crs).toEqual([{ id: a.cr.id }]);
    expect(new Set(seen.audit.map((e) => e.tenantId))).toEqual(new Set([TENANT_A]));
  });

  it("bank B's rows cannot be read by id, updated or deleted from inside withTenant(A)", async () => {
    const { b } = await seed();
    await withTenant(TENANT_A, async (tx) => {
      expect(await tx.ring.findUnique({ where: { id: b.ring.id } })).toBeNull();
      expect(await tx.changeRequest.findUnique({ where: { id: b.cr.id } })).toBeNull();
      expect((await tx.endpoint.updateMany({ where: { id: b.endpoint.id }, data: { hostname: "pwned" } })).count).toBe(0);
      expect((await tx.discoveredApp.deleteMany({ where: { id: b.discovered.id } })).count).toBe(0);
      expect((await tx.changeRequest.updateMany({ where: { id: b.cr.id }, data: { status: "APPROVED" } })).count).toBe(0);
    });
    expect((await prisma.endpoint.findUniqueOrThrow({ where: { id: b.endpoint.id } })).hostname).toBe("B-PC1");
    expect((await prisma.changeRequest.findUniqueOrThrow({ where: { id: b.cr.id } })).status).toBe("PENDING_APPROVAL");
    expect(await prisma.discoveredApp.count({ where: { id: b.discovered.id } })).toBe(1);
  });

  it("rejects writes of bank B rows from inside withTenant(A)", async () => {
    const { b } = await seed();
    await expect(
      withTenant(TENANT_A, (tx) => tx.ring.create({ data: { tenantId: TENANT_B, name: "Sneaky", wsusGroup: "Sneaky", order: 5 } })),
    ).rejects.toThrow(/row-level security/);
    await expect(
      withTenant(TENANT_A, (tx) => tx.endpoint.create({ data: { tenantId: TENANT_B, tacticalAgentId: "agentSneaky01", hostname: "X" } })),
    ).rejects.toThrow(/row-level security/);
    // Moving an own row into another bank is rejected as well (WITH CHECK on UPDATE).
    const ownRing = await prisma.ring.findFirstOrThrow({ where: { tenantId: TENANT_A } });
    await expect(
      withTenant(TENANT_A, (tx) => tx.ring.update({ where: { id: ownRing.id }, data: { tenantId: TENANT_B } })),
    ).rejects.toThrow(/row-level security/);
    // Appending to another bank's audit chain from a bank-scoped transaction fails too.
    await expect(
      withTenant(TENANT_A, (tx) => appendAudit({ tenantId: TENANT_B, actor: "x", action: "x", entity: "x", entityId: "x" }, tx)),
    ).rejects.toThrow(/cannot write the tenant-bank-b chain/);
    // ...and RLS backs that up even if the scope check were bypassed.
    await expect(
      withTenant(TENANT_A, (tx) =>
        tx.auditEvent.create({ data: { tenantId: TENANT_B, actor: "x", action: "x", entity: "x", entityId: "x", payload: {}, prevHash: "0", hash: "h-sneaky" } }),
      ),
    ).rejects.toThrow(/row-level security/);
    expect(await prisma.ring.count({ where: { name: "Sneaky" } })).toBe(0);
    expect(await prisma.ring.count({ where: { tenantId: TENANT_B } })).toBe(1);
    expect(b.ring.tenantId).toBe(TENANT_B);
  });

  it("withPlatform sees every bank; settings never leak to the next transaction on a pooled connection", async () => {
    await seed();
    expect(await withPlatform((tx) => tx.ring.count())).toBe(2);
    await withTenant(TENANT_A, (tx) => tx.ring.count());
    const after = await prisma.$queryRaw<{ t: string | null; s: string | null; r: string }[]>`
      SELECT current_setting('app.tenant_id', true) AS t, current_setting('app.scope', true) AS s, current_user AS r`;
    expect(after[0].t ?? "").toBe("");
    expect(after[0].s ?? "").toBe("");
    expect(after[0].r).not.toBe("patchgate_tenant");
  });

  it("rejects a malformed tenant id before touching the database", async () => {
    await expect(withTenant("x' OR '1'='1", async () => 1)).rejects.toThrow(/invalid tenant id/);
  });
});

describe("API-level isolation between banks", () => {
  it("a bank B approver gets 404 for bank A's change request (approve, deploy, cancel)", async () => {
    const { a } = await seed();
    ctx.user = (await prisma.user.findUniqueOrThrow({ where: { upn: "approver@b" } })) as TestUser;
    for (const action of ["approve", "reject", "deploy", "cancel"]) {
      const res = await crAction.POST(req("POST", `/api/change-requests/${a.cr.id}/${action}`, {}), params({ id: a.cr.id, action }));
      expect(res.status).toBe(404);
    }
    expect((await prisma.changeRequest.findUniqueOrThrow({ where: { id: a.cr.id } })).status).toBe("PENDING_APPROVAL");
  });

  it("a bank user only lists their own bank's change requests, even with a forged pg_tenant cookie", async () => {
    const { b } = await seed();
    ctx.user = (await prisma.user.findUniqueOrThrow({ where: { upn: "approver@b" } })) as TestUser;
    ctx.tenantCookie = TENANT_A; // ignored for bank users
    const body = await json(await crCollection.GET());
    expect((body.data as { id: string }[]).map((c) => c.id)).toEqual([b.cr.id]);
  });

  it("a bank B admin cannot re-ring bank A's PC or touch bank A's discovery (404)", async () => {
    const { a, b } = await seed();
    ctx.user = (await prisma.user.findUniqueOrThrow({ where: { upn: "admin@b" } })) as TestUser;
    const r1 = await endpointRoute.PATCH(req("PATCH", `/api/endpoints/${a.endpoint.id}`, { ringId: null }), params({ id: a.endpoint.id }));
    expect(r1.status).toBe(404);
    // own endpoint + another bank's ring: also refused
    const r2 = await endpointRoute.PATCH(req("PATCH", `/api/endpoints/${b.endpoint.id}`, { ringId: a.ring.id }), params({ id: b.endpoint.id }));
    expect(r2.status).toBe(404);
    const r3 = await discoveryRoute.POST(req("POST", `/api/discovery/${a.discovered.id}/ignore`, {}), params({ id: a.discovered.id, action: "ignore" }));
    expect(r3.status).toBe(404);
    expect((await prisma.endpoint.findUniqueOrThrow({ where: { id: a.endpoint.id } })).ringId).toBe(a.ring.id);
    expect((await prisma.discoveredApp.findUniqueOrThrow({ where: { id: a.discovered.id } })).ignored).toBe(false);
  });

  it("a bank user cannot create a change request on another bank's ring", async () => {
    const { a, patch } = await seed();
    ctx.user = (await prisma.user.findUniqueOrThrow({ where: { upn: "admin@b" } })) as TestUser;
    const res = await crCollection.POST(req("POST", "/api/change-requests", { title: "sneaky", ringId: a.ring.id, patchIds: [patch.id] }));
    expect(res.status).toBe(404);
  });

  it("patch 'needed' counts come from the active bank's PCs only", async () => {
    await seed();
    await prisma.endpointPatchState.updateMany({ where: { tenantId: TENANT_B }, data: { status: "INSTALLED" } });
    ctx.user = (await prisma.user.findUniqueOrThrow({ where: { upn: "approver@b" } })) as TestUser;
    const b = await json(await patchesRoute.GET(req("GET", "/api/patches")));
    expect((b.data as { items: { _count: { states: number } }[] }).items[0]._count.states).toBe(0);
    ctx.user = (await prisma.user.findUniqueOrThrow({ where: { upn: "approver@a" } })) as TestUser;
    const a = await json(await patchesRoute.GET(req("GET", "/api/patches")));
    expect((a.data as { items: { _count: { states: number } }[] }).items[0]._count.states).toBe(1);
  });
});

describe("bank switcher for platform staff", () => {
  it("platform staff without a selected bank get a clear 409 on bank-scoped APIs", async () => {
    await seed();
    ctx.user = (await prisma.user.findUniqueOrThrow({ where: { upn: "operator@pg" } })) as TestUser;
    const res = await crCollection.GET();
    expect(res.status).toBe(409);
    expect((await json(res)).error).toMatch(/select a bank/i);
  });

  it("with the cookie, platform staff act for exactly that bank", async () => {
    const { a, b } = await seed();
    ctx.user = (await prisma.user.findUniqueOrThrow({ where: { upn: "operator@pg" } })) as TestUser;
    ctx.tenantCookie = TENANT_A;
    expect(((await json(await crCollection.GET())).data as { id: string }[]).map((c) => c.id)).toEqual([a.cr.id]);
    ctx.tenantCookie = TENANT_B;
    expect(((await json(await crCollection.GET())).data as { id: string }[]).map((c) => c.id)).toEqual([b.cr.id]);
  });

  it("a cookie naming a suspended or unknown bank is ignored (no bank selected)", async () => {
    await seed();
    await prisma.tenant.update({ where: { id: TENANT_B }, data: { active: false } });
    ctx.user = (await prisma.user.findUniqueOrThrow({ where: { upn: "operator@pg" } })) as TestUser;
    for (const cookie of [TENANT_B, "no-such-bank", "bad id;"]) {
      ctx.tenantCookie = cookie;
      expect((await crCollection.GET()).status).toBe(409);
    }
  });

  it("select: platform staff may switch (audited, platform chain); bank users get 403; bad banks 404", async () => {
    await seed();
    ctx.user = (await prisma.user.findUniqueOrThrow({ where: { upn: "operator@pg" } })) as TestUser;
    const ok = await tenantSelect.POST(req("POST", "/api/tenant/select", { tenantId: TENANT_B }));
    expect(ok.status).toBe(200);
    expect(ctx.setCookies).toEqual([["pg_tenant", TENANT_B]]);
    const audit = await prisma.auditEvent.findFirstOrThrow({ where: { action: "tenant.select" } });
    expect(audit).toMatchObject({ tenantId: null, actor: "operator@pg", entityId: TENANT_B });

    expect((await tenantSelect.POST(req("POST", "/api/tenant/select", { tenantId: "no-such-bank" }))).status).toBe(404);
    expect((await tenantSelect.POST(req("POST", "/api/tenant/select", { tenantId: "../etc" }))).status).toBe(400);

    ctx.user = (await prisma.user.findUniqueOrThrow({ where: { upn: "approver@b" } })) as TestUser;
    expect((await tenantSelect.POST(req("POST", "/api/tenant/select", { tenantId: TENANT_A }))).status).toBe(403);
  });

  it("select is same-origin protected", async () => {
    await seed();
    ctx.user = (await prisma.user.findUniqueOrThrow({ where: { upn: "operator@pg" } })) as TestUser;
    const cross = new Request(`${ORIGIN}/api/tenant/select`, {
      method: "POST",
      headers: { origin: "https://evil.example", "x-forwarded-host": "patchgate.test", "content-type": "application/json" },
      body: JSON.stringify({ tenantId: TENANT_A }),
    });
    expect((await tenantSelect.POST(cross)).status).toBe(403);
    expect(ctx.setCookies).toEqual([]);
  });
});

describe("per-bank maker-checker policy", () => {
  it("requireBankApproval (default): platform admin cannot approve; the bank's approver can", async () => {
    const { a } = await seed();
    ctx.user = (await prisma.user.findUniqueOrThrow({ where: { upn: "admin@pg" } })) as TestUser;
    ctx.tenantCookie = TENANT_A;
    const denied = await crAction.POST(req("POST", `/api/change-requests/${a.cr.id}/approve`, {}), params({ id: a.cr.id, action: "approve" }));
    expect(denied.status).toBe(409);
    expect((await json(denied)).error).toMatch(/bank approval required/i);

    ctx.user = (await prisma.user.findUniqueOrThrow({ where: { upn: "approver@a" } })) as TestUser;
    ctx.tenantCookie = undefined;
    const okRes = await crAction.POST(req("POST", `/api/change-requests/${a.cr.id}/approve`, {}), params({ id: a.cr.id, action: "approve" }));
    expect(okRes.status).toBe(200);
    const cr = await prisma.changeRequest.findUniqueOrThrow({ where: { id: a.cr.id }, include: { approvedBy: true } });
    expect(cr.status).toBe("APPROVED");
    expect(cr.approvedBy?.upn).toBe("approver@a");
    // recorded in bank A's chain only
    const ev = await prisma.auditEvent.findFirstOrThrow({ where: { action: "change_request.approve" } });
    expect(ev.tenantId).toBe(TENANT_A);
  });

  it("bank approval cannot be switched off: our team can never be the only checker", async () => {
    const { users, a } = await seed();
    await expect(prisma.tenant.update({ where: { id: TENANT_A }, data: { requireBankApproval: false } })).rejects.toThrow(/Tenant_requireBankApproval_always|check constraint/i);
    await expect(applyAction(users.platformAdmin, TENANT_A, a.cr.id, "approve")).rejects.toThrow();
    expect((await prisma.changeRequest.findUniqueOrThrow({ where: { id: a.cr.id } })).status).not.toBe("APPROVED");
  });

  it("services refuse a bank user acting for another bank even if called directly", async () => {
    const { users, a } = await seed();
    await expect(applyAction(users.approverB, TENANT_A, a.cr.id, "approve")).rejects.toThrow(/Not allowed for this bank/);
  });
});

describe("platform-only decisions", () => {
  it("bank admins cannot make trust decisions on shared packages (403)", async () => {
    await seed();
    ctx.user = (await prisma.user.findUniqueOrThrow({ where: { upn: "admin@b" } })) as TestUser;
    const res = await packageDecision.POST(req("POST", "/api/packages/x/approve", {}), params({ id: "x", decision: "approve" }));
    expect(res.status).toBe(403);
  });

  it("a bank admin can opt their bank in/out of a shared app without affecting other banks", async () => {
    await seed();
    const app = await prisma.app.create({ data: { wingetId: "Git.Git", displayName: "Git", inventoryMatch: "^Git$", allowedDomains: [] } });
    ctx.user = (await prisma.user.findUniqueOrThrow({ where: { upn: "admin@b" } })) as TestUser;
    const on = await appToggle.POST(req("POST", `/api/apps/${app.id}/enable`, {}), params({ id: app.id, action: "enable" }));
    expect(on.status).toBe(200);
    expect(await prisma.tenantApp.findMany({ select: { tenantId: true } })).toEqual([{ tenantId: TENANT_B }]);
    // bank B's discovered Git is now linked; bank A's is untouched
    expect((await prisma.discoveredApp.findFirstOrThrow({ where: { tenantId: TENANT_B } })).appId).toBe(app.id);
    expect((await prisma.discoveredApp.findFirstOrThrow({ where: { tenantId: TENANT_A } })).appId).toBeNull();
    expect((await prisma.auditEvent.findFirstOrThrow({ where: { action: "tenant_app.enable" } })).tenantId).toBe(TENANT_B);

    const off = await appToggle.POST(req("POST", `/api/apps/${app.id}/disable`, {}), params({ id: app.id, action: "disable" }));
    expect(off.status).toBe(200);
    expect(await prisma.tenantApp.count()).toBe(0);
    expect((await prisma.discoveredApp.findFirstOrThrow({ where: { tenantId: TENANT_B } })).appId).toBeNull();
  });
});
