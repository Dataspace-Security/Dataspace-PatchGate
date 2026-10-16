/**
 * Security regressions for sign-in / administration (findings #3, #4, #5, #7, #8) against real PostgreSQL.
 * Run: TEST_DATABASE_URL=postgresql://…/patchgate_test_auth npm run test:int -- src/test/auth-security.int.test.ts
 */
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { configureTestEnv, resetDb } from "./helpers";

configureTestEnv({ AUTH_MODE: "local", AUTH_ENC_KEY: "ab".repeat(32) });

const { prisma } = await import("@/lib/db");
const { beginPasswordLogin, changePasswordStep } = await import("@/lib/auth/local-login");
const { createUser, updateUser, userAction, createTenant } = await import("@/lib/auth/admin-service");
const { hashPassword } = await import("@/lib/auth/password");
const { flushUnknownLoginSummary, resetUnknownLoginSummary } = await import("@/lib/auth/unknown-login-summary");
const { resolveOidcAccount } = await import("@/lib/auth/oidc");
const { auditTenantSwitch } = await import("@/lib/auth/vendor-access");
const { recentAdminEvents } = await import("@/lib/auth/admin-overview");
const { verifyAuditLog } = await import("@/lib/audit/service");
type SessionUser = import("@/lib/auth/session").SessionUser;
type LoginStep = import("@/lib/auth/local-login").LoginStep;

const META = { ip: "10.0.0.1", userAgent: "vitest" };
const STRONG = "orbit-Kettle-7-sandstone-river";
const STRONG2 = "quartz-Lantern-9-meadow-falcon";
const asActor = (u: { id: string; role: SessionUser["role"]; upn: string; name: string; tenantId: string | null }): SessionUser => ({ id: u.id, role: u.role, upn: u.upn, name: u.name, tenantId: u.tenantId });

function expectStep<S extends Extract<LoginStep, { ok: true }>["step"]>(r: LoginStep, step: S): Extract<LoginStep, { step: S }> {
  if (!r.ok) throw new Error(`expected ${step}, got error: ${r.error}`);
  expect(r.step).toBe(step);
  return r as Extract<LoginStep, { step: S }>;
}

beforeEach(async () => {
  await resetDb(prisma);
  await prisma.$executeRawUnsafe(`TRUNCATE "AuthChallenge", "Session", "Tenant" CASCADE`);
  resetUnknownLoginSummary();
});
afterAll(() => prisma.$disconnect());

async function setup() {
  const rootRow = await prisma.user.create({ data: { upn: "root@platform.test", name: "Root", role: "ADMIN", passwordHash: await hashPassword(STRONG) } });
  const root = asActor(rootRow);
  const bank = await createTenant(root, { slug: "bank-a", name: "Bank A", active: true, requireBankApproval: true });
  const other = await createTenant(root, { slug: "bank-b", name: "Bank B", active: true, requireBankApproval: true });
  const bankAdmin = asActor((await createUser(root, { upn: "admin@bank-a.test", name: "Admin A", role: "ADMIN", tenantId: bank.id })).user);
  return { root, bank, other, bankAdmin };
}

/** First sign-in with a temporary password: change it, get a session. */
async function firstLogin(upn: string, temporaryPassword: string, when: Date): Promise<void> {
  const change = expectStep(await beginPasswordLogin({ upn, password: temporaryPassword }, META, when), "change-password");
  expectStep(await changePasswordStep(change.challengeToken, STRONG, META, when), "done");
}

const lastLogin = async (userId: string) =>
  prisma.auditEvent.findFirstOrThrow({ where: { action: "auth.login", entityId: userId }, orderBy: { seq: "desc" } });

describe("finding #3: credential resets are platform-only (accounts are issued by PatchGate)", () => {
  it("a bank admin cannot reset, unlock, re-role or create any account; a platform admin can (bank chain)", async () => {
    const { root, bank, bankAdmin } = await setup();
    const approver = (await createUser(root, { upn: "checker@bank-a.test", name: "Checker", role: "ADMIN", tenantId: bank.id })).user;
    const aud = (await createUser(root, { upn: "aud@bank-a.test", name: "Aud", role: "AUDITOR", tenantId: bank.id })).user;
    const before = await prisma.user.findMany({ orderBy: { upn: "asc" } });

    for (const target of [approver.id, aud.id]) {
      for (const action of ["reset-password", "unlock"] as const) {
        await expect(userAction(bankAdmin, target, action)).rejects.toMatchObject({ status: 403 });
      }
      await expect(updateUser(bankAdmin, target, { role: "ADMIN" })).rejects.toMatchObject({ status: 403 });
    }
    // the maker-checker gap: a bank admin may not mint a second admin (and learn its temporary password)
    await expect(createUser(bankAdmin, { upn: "sock@bank-a.test", name: "Sock puppet", role: "ADMIN", tenantId: bank.id })).rejects.toMatchObject({ status: 403 });
    expect(await prisma.user.findMany({ orderBy: { upn: "asc" } })).toEqual(before);
    expect(await prisma.auditEvent.count({ where: { actor: bankAdmin.upn } })).toBe(0);

    const r = await userAction(root, approver.id, "reset-password");
    expect(r.temporaryPassword).toBeTruthy();
    const ev = await prisma.auditEvent.findFirstOrThrow({ where: { action: "user.password_reset", entityId: approver.id } });
    expect(ev.tenantId).toBe(bank.id); // the BANK chain
    expect(ev.payload).toMatchObject({ targetRole: "ADMIN", nextLoginFlagged: true });
    expect((await verifyAuditLog(bank.id)).valid).toBe(true);
  });

  it("the retired roles can no longer be granted (zod) and the database refuses them (User_role_scope)", async () => {
    const { root, bank, bankAdmin } = await setup();
    for (const role of ["VIEWER", "OPERATOR", "APPROVER"]) {
      await expect(createUser(root, { upn: `x-${role}@bank-a.test`, name: "X", role: role as "ADMIN", tenantId: bank.id })).rejects.toThrow();
      await expect(updateUser(root, bankAdmin.id, { role: role as "ADMIN" })).rejects.toThrow();
    }
    await expect(prisma.user.create({ data: { upn: "p-approver@pg.test", name: "P", role: "APPROVER" } })).rejects.toThrow(/User_role_scope/);
    await expect(prisma.user.create({ data: { upn: "b-viewer@bank-a.test", name: "B", role: "VIEWER", tenantId: bank.id } })).rejects.toThrow(/User_role_scope/);
    await expect(prisma.user.update({ where: { id: bankAdmin.id }, data: { role: "OPERATOR" } })).rejects.toThrow(/User_role_scope/);
    // both active roles are valid in both scopes
    await prisma.user.create({ data: { upn: "p-aud@pg.test", name: "P", role: "AUDITOR" } });
    await prisma.user.create({ data: { upn: "b-aud@bank-a.test", name: "B", role: "AUDITOR", tenantId: bank.id } });
    expect((await prisma.user.create({ data: { upn: "default@pg.test", name: "D" } })).role).toBe("AUDITOR"); // safe default
  });

  it("the first sign-in after a reset is flagged afterReset=true (SIEM alert); later ones are not", async () => {
    const { root, bank } = await setup();
    const { user, temporaryPassword } = await createUser(root, { upn: "teller@bank-a.test", name: "Teller", role: "AUDITOR", tenantId: bank.id });
    const t0 = new Date(Date.now() - 120_000);
    await firstLogin(user.upn, temporaryPassword, t0);
    expect((await lastLogin(user.id)).payload).not.toHaveProperty("afterReset");

    // password reset: the next sign-in (forced change of the temporary password) is flagged
    const r = await userAction(root, user.id, "reset-password");
    const t1 = new Date(Date.now() + 30_000);
    const ch = expectStep(await beginPasswordLogin({ upn: user.upn, password: r.temporaryPassword! }, META, t1), "change-password");
    expectStep(await changePasswordStep(ch.challengeToken, STRONG2, META, t1), "done");
    const flagged = await lastLogin(user.id);
    expect(flagged.tenantId).toBe(bank.id);
    expect(flagged.payload).toMatchObject({ afterReset: true, resetAction: "user.password_reset", resetBy: root.upn });

    // later sign-ins are not flagged
    const t2 = new Date(Date.now() + 90_000);
    expectStep(await beginPasswordLogin({ upn: user.upn, password: STRONG2 }, META, t2), "done");
    expect((await lastLogin(user.id)).payload).not.toHaveProperty("afterReset");
  });
});

describe("finding #5: failed logins for unknown names are aggregated", () => {
  it("no per-attempt event with the attacker's name; one summary; known users still audited individually", async () => {
    const { root } = await setup();
    const t = new Date();
    for (let i = 0; i < 25; i++) {
      await beginPasswordLogin({ upn: `spray-${i}-${"x".repeat(50)}@evil.test`, password: "whatever-password" }, { ...META, ip: `203.0.113.${i % 3}` }, t);
    }
    expect(await prisma.auditEvent.count({ where: { action: "auth.failed" } })).toBe(0);
    expect(await prisma.auditEvent.count({ where: { actor: { contains: "spray" } } })).toBe(0);
    expect(await flushUnknownLoginSummary(t.getTime() + 61_000)).toBe(25);
    const sum = await prisma.auditEvent.findFirstOrThrow({ where: { action: "auth.failed_unknown_summary" } });
    expect(sum.tenantId).toBeNull();
    expect(sum.payload).toMatchObject({ failures: 25, distinctIps: 3, topIps: expect.arrayContaining([{ ip: "203.0.113.0", count: 9 }]) });
    expect(JSON.stringify(sum.payload)).not.toContain("spray");
    expect(await flushUnknownLoginSummary(t.getTime() + 200_000, true)).toBe(0); // nothing left

    await beginPasswordLogin({ upn: root.upn, password: "not-the-password-xx" }, META, t);
    const known = await prisma.auditEvent.findFirstOrThrow({ where: { action: "auth.failed" } });
    expect(known).toMatchObject({ actor: root.upn, entityId: root.id });
    expect((await verifyAuditLog(null)).valid).toBe(true);
  });
});

describe("finding #7: OIDC matches linked accounts by subject only", () => {
  it("never falls back to the UPN once an account is linked", async () => {
    const linked = await prisma.user.create({ data: { upn: "alice@bank.test", name: "Alice", role: "ADMIN", externalId: "oid-alice" } });
    const unlinked = await prisma.user.create({ data: { upn: "bob@bank.test", name: "Bob", role: "AUDITOR" } });

    expect(await resolveOidcAccount("oid-alice", "alice@bank.test")).toMatchObject({ ok: true, user: { id: linked.id } });
    // renamed in the directory: still the same account (by subject)
    expect(await resolveOidcAccount("oid-alice", "alice.new@bank.test")).toMatchObject({ ok: true, user: { id: linked.id } });
    // another directory account claiming Alice's UPN: refused, never matched by UPN
    expect(await resolveOidcAccount("oid-mallory", "alice@bank.test")).toMatchObject({ ok: false, reason: expect.stringContaining("already linked") });
    // first link of an unlinked local account by UPN, exactly once
    expect(await resolveOidcAccount("oid-bob", "bob@bank.test")).toMatchObject({ ok: true, user: { id: unlinked.id } });
    // a linked subject whose new UPN belongs to someone else: refused (no takeover / no crash)
    expect(await resolveOidcAccount("oid-alice", "bob@bank.test")).toMatchObject({ ok: false });
    // unknown subject + unknown UPN: new account
    expect(await resolveOidcAccount("oid-new", "new@bank.test")).toEqual({ ok: true, user: null });
  });
});

describe("finding #4: vendor (platform staff) access is on the bank's chain too", () => {
  it("select + clear write to the platform chain AND the bank's chain with role and IP", async () => {
    const { root, bank, other } = await setup();
    await auditTenantSwitch(root, { bank: { id: bank.id, slug: "bank-a" }, previousTenantId: null }, "198.51.100.7");
    await auditTenantSwitch({ upn: "viewer@platform.test", role: "AUDITOR" }, { bank: { id: other.id, slug: "bank-b" }, previousTenantId: bank.id }, "198.51.100.8");
    const bankEvents = await prisma.auditEvent.findMany({ where: { tenantId: bank.id, action: { in: ["tenant.select", "tenant.clear"] } }, orderBy: { seq: "asc" } });
    expect(bankEvents.map((e) => [e.action, e.actor])).toEqual([
      ["tenant.select", root.upn],
      ["tenant.clear", "viewer@platform.test"],
    ]);
    expect(bankEvents[0].payload).toMatchObject({ role: "ADMIN", ip: "198.51.100.7", vendorAccess: true });
    const b = await prisma.auditEvent.findFirstOrThrow({ where: { tenantId: other.id, action: "tenant.select" } });
    expect(b.payload).toMatchObject({ role: "AUDITOR", ip: "198.51.100.8" });
    expect(await prisma.auditEvent.count({ where: { tenantId: null, action: "tenant.select" } })).toBe(2);
    for (const chain of [null, bank.id, other.id]) expect((await verifyAuditLog(chain)).valid).toBe(true);
  });
});

describe("finding #8: admin overview reads audit events through an RLS scope", () => {
  it("a plain query under the runtime role sees nothing; the scoped helper sees the right chains", async () => {
    const { root, bank, other, bankAdmin } = await setup();
    await createUser(root, { upn: "b@bank-b.test", name: "B", role: "AUDITOR", tenantId: other.id });
    // what the old page did, as the non-owner runtime role: RLS hides every row
    const plain = await prisma.$transaction(async (tx) => {
      await tx.$executeRawUnsafe(`SET LOCAL role patchgate_tenant`);
      return tx.auditEvent.count({ where: { action: "user.created" } });
    });
    expect(plain).toBe(0);

    const platform = await recentAdminEvents(null, 50);
    expect(new Set(platform.map((e) => e.tenantId))).toEqual(new Set([null, bank.id, other.id]));
    const own = await recentAdminEvents(bankAdmin.tenantId, 50);
    expect(own.length).toBeGreaterThan(0);
    expect(own.every((e) => e.tenantId === bank.id)).toBe(true);
  });
});
