/**
 * Security regressions for sign-in / administration (findings #3, #4, #5, #7, #8) against real PostgreSQL.
 * Run: TEST_DATABASE_URL=postgresql://…/patchgate_test_auth npm run test:int -- src/test/auth-security.int.test.ts
 */
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { configureTestEnv, resetDb } from "./helpers";

configureTestEnv({ AUTH_MODE: "local", AUTH_ENC_KEY: "ab".repeat(32) });

const { prisma } = await import("@/lib/db");
const { beginPasswordLogin, verifyTotpStep, changePasswordStep } = await import("@/lib/auth/local-login");
const { createUser, updateUser, userAction, createTenant, canResetCredentials } = await import("@/lib/auth/admin-service");
const { hashPassword } = await import("@/lib/auth/password");
const { base32Decode, hotp, totpStep } = await import("@/lib/auth/totp");
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
const codeFor = (secret: string, when: Date) => hotp(base32Decode(secret), totpStep(when.getTime()));
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

/** First sign-in with a temporary password: enrol TOTP, change password. Returns the TOTP secret. */
async function firstLogin(upn: string, temporaryPassword: string, when: Date): Promise<string> {
  const enrol = expectStep(await beginPasswordLogin({ upn, password: temporaryPassword }, META, when), "enroll");
  const change = expectStep(await verifyTotpStep(enrol.challengeToken, codeFor(enrol.secret, when), META, when), "change-password");
  expectStep(await changePasswordStep(change.challengeToken, STRONG, META, when), "done");
  return enrol.secret.replace(/\s+/g, "");
}

const lastLogin = async (userId: string) =>
  prisma.auditEvent.findFirstOrThrow({ where: { action: "auth.login", entityId: userId }, orderBy: { seq: "desc" } });

describe("finding #3: credential resets of approvers / admins", () => {
  it("rule table", () => {
    expect(canResetCredentials("bank", "reset-password", "OPERATOR")).toBe(true);
    expect(canResetCredentials("bank", "reset-mfa", "VIEWER")).toBe(true);
    expect(canResetCredentials("bank", "reset-password", "APPROVER")).toBe(false);
    expect(canResetCredentials("bank", "reset-mfa", "ADMIN")).toBe(false);
    expect(canResetCredentials("bank", "unlock", "APPROVER")).toBe(true);
    expect(canResetCredentials("platform", "reset-password", "APPROVER")).toBe(true);
  });

  it("a bank admin cannot reset an approver (audited on the bank chain); a platform admin can", async () => {
    const { root, bank, bankAdmin } = await setup();
    const approver = (await createUser(root, { upn: "checker@bank-a.test", name: "Checker", role: "APPROVER", tenantId: bank.id })).user;
    const before = await prisma.user.findUniqueOrThrow({ where: { id: approver.id } });

    for (const action of ["reset-password", "reset-mfa"] as const) {
      await expect(userAction(bankAdmin, approver.id, action)).rejects.toMatchObject({ status: 403 });
    }
    const after = await prisma.user.findUniqueOrThrow({ where: { id: approver.id } });
    expect(after.passwordHash).toBe(before.passwordHash);
    const denied = await prisma.auditEvent.findMany({ where: { action: "user.reset_denied" } });
    expect(denied).toHaveLength(2);
    expect(denied.every((e) => e.tenantId === bank.id && e.actor === bankAdmin.upn)).toBe(true);
    // another bank admin, too
    const admin2 = (await createUser(root, { upn: "admin2@bank-a.test", name: "Admin 2", role: "ADMIN", tenantId: bank.id })).user;
    await expect(userAction(bankAdmin, admin2.id, "reset-password")).rejects.toMatchObject({ status: 403 });
    // unlock reveals nothing: allowed
    await userAction(bankAdmin, approver.id, "unlock");

    const r = await userAction(root, approver.id, "reset-password");
    expect(r.temporaryPassword).toBeTruthy();
    const ev = await prisma.auditEvent.findFirstOrThrow({ where: { action: "user.password_reset", entityId: approver.id } });
    expect(ev.tenantId).toBe(bank.id); // the BANK chain
    expect(ev.payload).toMatchObject({ targetRole: "APPROVER", byPlatformAdmin: true, nextLoginFlagged: true });
    expect((await verifyAuditLog(bank.id)).valid).toBe(true);
  });

  it("closes demote → reset → promote: a bank admin may not re-grant approver for 30 days", async () => {
    const { root, bank, bankAdmin } = await setup();
    const approver = (await createUser(root, { upn: "checker@bank-a.test", name: "Checker", role: "APPROVER", tenantId: bank.id })).user;
    await updateUser(bankAdmin, approver.id, { role: "OPERATOR" });
    await userAction(bankAdmin, approver.id, "reset-password");
    await expect(updateUser(bankAdmin, approver.id, { role: "APPROVER" })).rejects.toMatchObject({ status: 403 });
    await expect(updateUser(bankAdmin, approver.id, { role: "ADMIN" })).rejects.toMatchObject({ status: 403 });
    expect((await prisma.user.findUniqueOrThrow({ where: { id: approver.id } })).role).toBe("OPERATOR");
    await updateUser(root, approver.id, { role: "APPROVER" }); // platform admin decides
    // no reset → promotion by the bank admin is fine
    const op = (await createUser(bankAdmin, { upn: "op@bank-a.test", name: "Op", role: "OPERATOR" })).user;
    await updateUser(bankAdmin, op.id, { role: "APPROVER" });
  });

  it("the first sign-in after a reset is flagged afterReset=true (SIEM alert); later ones are not", async () => {
    const { bank, bankAdmin } = await setup();
    const { user, temporaryPassword } = await createUser(bankAdmin, { upn: "teller@bank-a.test", name: "Teller", role: "OPERATOR" });
    const t0 = new Date(Date.now() - 120_000);
    const secret0 = await firstLogin(user.upn, temporaryPassword, t0);
    expect((await lastLogin(user.id)).payload).not.toHaveProperty("afterReset");
    expect(secret0).toBeTruthy();

    await userAction(bankAdmin, user.id, "reset-mfa");
    const t1 = new Date(Date.now() + 30_000);
    const enrol = expectStep(await beginPasswordLogin({ upn: user.upn, password: STRONG }, META, t1), "enroll");
    expectStep(await verifyTotpStep(enrol.challengeToken, codeFor(enrol.secret, t1), META, t1), "done");
    const flagged = await lastLogin(user.id);
    expect(flagged.tenantId).toBe(bank.id);
    expect(flagged.payload).toMatchObject({ afterReset: true, resetAction: "user.mfa_reset", resetBy: bankAdmin.upn });

    const t2 = new Date(Date.now() + 90_000);
    const v = expectStep(await beginPasswordLogin({ upn: user.upn, password: STRONG }, META, t2), "verify");
    expectStep(await verifyTotpStep(v.challengeToken, codeFor(enrol.secret.replace(/\s+/g, ""), t2), META, t2), "done");
    expect((await lastLogin(user.id)).payload).not.toHaveProperty("afterReset");

    // password reset: flagged on the forced-change path (the logins above used future clocks for TOTP steps)
    await prisma.user.update({ where: { id: user.id }, data: { lastLoginAt: new Date(Date.now() - 1000) } });
    const r = await userAction(bankAdmin, user.id, "reset-password");
    const t3 = new Date(Date.now() + 150_000);
    const v3 = expectStep(await beginPasswordLogin({ upn: user.upn, password: r.temporaryPassword! }, META, t3), "verify");
    const ch = expectStep(await verifyTotpStep(v3.challengeToken, codeFor(enrol.secret.replace(/\s+/g, ""), t3), META, t3), "change-password");
    expectStep(await changePasswordStep(ch.challengeToken, STRONG2, META, t3), "done");
    expect((await lastLogin(user.id)).payload).toMatchObject({ afterReset: true, resetAction: "user.password_reset" });
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
    const linked = await prisma.user.create({ data: { upn: "alice@bank.test", name: "Alice", role: "APPROVER", externalId: "oid-alice" } });
    const unlinked = await prisma.user.create({ data: { upn: "bob@bank.test", name: "Bob", role: "VIEWER" } });

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
    await auditTenantSwitch({ upn: "viewer@platform.test", role: "VIEWER" }, { bank: { id: other.id, slug: "bank-b" }, previousTenantId: bank.id }, "198.51.100.8");
    const bankEvents = await prisma.auditEvent.findMany({ where: { tenantId: bank.id, action: { in: ["tenant.select", "tenant.clear"] } }, orderBy: { seq: "asc" } });
    expect(bankEvents.map((e) => [e.action, e.actor])).toEqual([
      ["tenant.select", root.upn],
      ["tenant.clear", "viewer@platform.test"],
    ]);
    expect(bankEvents[0].payload).toMatchObject({ role: "ADMIN", ip: "198.51.100.7", vendorAccess: true });
    const b = await prisma.auditEvent.findFirstOrThrow({ where: { tenantId: other.id, action: "tenant.select" } });
    expect(b.payload).toMatchObject({ role: "VIEWER", ip: "198.51.100.8" });
    expect(await prisma.auditEvent.count({ where: { tenantId: null, action: "tenant.select" } })).toBe(2);
    for (const chain of [null, bank.id, other.id]) expect((await verifyAuditLog(chain)).valid).toBe(true);
  });
});

describe("finding #8: admin overview reads audit events through an RLS scope", () => {
  it("a plain query under the runtime role sees nothing; the scoped helper sees the right chains", async () => {
    const { root, bank, other, bankAdmin } = await setup();
    await createUser(root, { upn: "b@bank-b.test", name: "B", role: "VIEWER", tenantId: other.id });
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
