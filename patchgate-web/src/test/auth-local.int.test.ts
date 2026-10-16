/**
 * Local sign-in (password only) and user/bank administration against a real PostgreSQL.
 * Run: TEST_DATABASE_URL=postgresql://…/patchgate_test_auth npm run test:int -- src/test/auth-local.int.test.ts
 */
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { configureTestEnv, resetDb } from "./helpers";

configureTestEnv({ AUTH_MODE: "local", AUTH_ENC_KEY: "ab".repeat(32) });

const { prisma } = await import("@/lib/db");
const { beginPasswordLogin, changePasswordStep, LOGIN_ERROR, RESTART_ERROR, MAX_CHALLENGE_ATTEMPTS } = await import("@/lib/auth/local-login");
const { createUser, updateUser, userAction, createTenant, updateTenant, listUsers, ACCOUNTS_MANAGED_BY_PLATFORM } = await import("@/lib/auth/admin-service");
const { verifyAuditLog } = await import("@/lib/audit/service");
const { hashPassword } = await import("@/lib/auth/password");
const { sha256Hex } = await import("@/lib/auth/tokens");
const { AuthError } = await import("@/lib/auth/session");
const { DomainError } = await import("@/lib/errors");
type SessionUser = import("@/lib/auth/session").SessionUser;
type LoginStep = import("@/lib/auth/local-login").LoginStep;

const META = { ip: "10.0.0.1", userAgent: "vitest" };
const T0 = new Date("2026-10-15T09:00:00Z");
const at = (seconds: number) => new Date(T0.getTime() + seconds * 1000);
const STRONG = "orbit-Kettle-7-sandstone-river";

async function resetAll() {
  await resetDb(prisma);
  await prisma.$executeRawUnsafe(`TRUNCATE "AuthChallenge", "Session", "Tenant" CASCADE`);
}

const asActor = (u: { id: string; role: SessionUser["role"]; upn: string; name: string; tenantId: string | null }): SessionUser => ({
  id: u.id,
  role: u.role,
  upn: u.upn,
  name: u.name,
  tenantId: u.tenantId,
});

async function platformAdmin(upn = "root@platform.test"): Promise<SessionUser> {
  const u = await prisma.user.create({ data: { upn, name: "Platform Admin", role: "ADMIN", passwordHash: await hashPassword(STRONG) } });
  return asActor(u);
}

function expectStep<S extends Extract<LoginStep, { ok: true }>["step"]>(r: LoginStep, step: S): Extract<LoginStep, { step: S }> {
  if (!r.ok) throw new Error(`expected ${step}, got error: ${r.error}`);
  expect(r.step).toBe(step);
  return r as Extract<LoginStep, { step: S }>;
}

async function auditActions(): Promise<string[]> {
  return (await prisma.auditEvent.findMany({ orderBy: { seq: "asc" }, select: { action: true } })).map((e) => e.action);
}

beforeEach(resetAll);
afterAll(() => prisma.$disconnect());

describe("local sign-in", () => {
  it("temporary password → forced password change → session; then normal sign-in (password only)", async () => {
    const root = await platformAdmin();
    const bank = await createTenant(root, { slug: "bank-a", name: "Bank A", active: true, requireBankApproval: true });
    // A new bank can open change requests immediately: standard rollout rings exist.
    const rings = await prisma.ring.findMany({ where: { tenantId: bank.id }, orderBy: { order: "asc" } });
    expect(rings.map((r) => r.name)).toEqual(["Ring0-Test", "Ring1-Pilot", "Ring2-Prod"]);
    const { user, temporaryPassword } = await createUser(root, { upn: "Alice@Bank-A.test", name: "Alice", role: "ADMIN", tenantId: bank.id });
    expect(user.upn).toBe("alice@bank-a.test");
    expect(user.mustChangePassword).toBe(true);
    const stored = await prisma.user.findUniqueOrThrow({ where: { id: user.id } });
    expect(stored.passwordHash).toMatch(/^scrypt\$/);
    expect(stored.passwordHash).not.toContain(temporaryPassword);

    const change = expectStep(await beginPasswordLogin({ upn: "alice@bank-a.test", password: temporaryPassword, returnTo: "/change-requests" }, META, T0), "change-password");
    const pending = await prisma.authChallenge.findUniqueOrThrow({ where: { id: sha256Hex(change.challengeToken) } });
    expect(pending.kind).toBe("PASSWORD");
    expect(await prisma.session.count()).toBe(0); // no session before the password is changed

    const weak = await changePasswordStep(change.challengeToken, "short", META, T0);
    expect(weak).toMatchObject({ ok: false, status: 400, restart: false });
    const reuse = await changePasswordStep(change.challengeToken, temporaryPassword, META, T0);
    expect(reuse).toMatchObject({ ok: false, error: expect.stringMatching(/different/) });

    const done = expectStep(await changePasswordStep(change.challengeToken, STRONG, META, T0), "done");
    expect(done.returnTo).toBe("/change-requests");
    const session = await prisma.session.findUniqueOrThrow({ where: { id: sha256Hex(done.sessionToken) } });
    expect(session.userId).toBe(user.id);
    expect(session.expiresAt.getTime() - T0.getTime()).toBe(8 * 3_600_000);
    const after = await prisma.user.findUniqueOrThrow({ where: { id: user.id } });
    expect(after).toMatchObject({ mustChangePassword: false, failedLogins: 0 });
    expect(await prisma.authChallenge.count()).toBe(0);
    // The password-change challenge is single use.
    expect(await changePasswordStep(change.challengeToken, "another-Strong-9-passphrase", META, at(10))).toMatchObject({ ok: false, restart: true });

    // Old temporary password no longer works; the new one signs in directly.
    expect(await beginPasswordLogin({ upn: "alice@bank-a.test", password: temporaryPassword }, META, at(60))).toMatchObject({ ok: false, error: LOGIN_ERROR });
    expectStep(await beginPasswordLogin({ upn: "alice@bank-a.test", password: STRONG }, META, at(90)), "done");

    const actions = await auditActions();
    for (const a of ["tenant.created", "user.created", "auth.password_changed", "auth.login", "auth.failed"]) expect(actions).toContain(a);
    const loginEvent = await prisma.auditEvent.findFirstOrThrow({ where: { action: "auth.login" } });
    expect(loginEvent.tenantId).toBe(bank.id); // bank user → bank's audit chain
    expect(loginEvent.payload).toMatchObject({ method: "password" });
  });

  it("uses one generic message for unknown users, wrong passwords and deactivated accounts", async () => {
    const root = await platformAdmin();
    const { user } = await createUser(root, { upn: "carol@platform.test", name: "Carol", role: "AUDITOR", tenantId: null });
    const unknown = await beginPasswordLogin({ upn: "nobody@platform.test", password: STRONG }, META, T0);
    const wrong = await beginPasswordLogin({ upn: user.upn, password: "not-the-password-at-all" }, META, T0);
    await updateUser(root, user.id, { active: false });
    const inactive = await beginPasswordLogin({ upn: user.upn, password: "whatever-password-here" }, META, T0);
    for (const r of [unknown, wrong, inactive]) expect(r).toEqual({ ok: false, error: LOGIN_ERROR, restart: false, status: 401 });
  });

  it("locks the account for 15 minutes after 5 consecutive failures (audited)", async () => {
    const root = await platformAdmin();
    for (let i = 0; i < 5; i++) {
      expect(await beginPasswordLogin({ upn: root.upn, password: `wrong-password-${i}-xx` }, META, at(i))).toMatchObject({ ok: false, error: LOGIN_ERROR });
    }
    const locked = await prisma.user.findUniqueOrThrow({ where: { id: root.id } });
    expect(locked.lockedUntil?.getTime()).toBe(at(4).getTime() + 15 * 60_000);
    expect(await auditActions()).toContain("auth.lockout");

    // Correct password while locked: same generic refusal, no session.
    expect(await beginPasswordLogin({ upn: root.upn, password: STRONG }, META, at(60))).toMatchObject({ ok: false, error: LOGIN_ERROR });
    expect(await prisma.session.count()).toBe(0);
    // After the lock expires, the password alone signs in.
    expectStep(await beginPasswordLogin({ upn: root.upn, password: STRONG }, META, at(16 * 60)), "done");
  });

  it("bad new passwords burn the password-change challenge after the attempt limit", async () => {
    const root = await platformAdmin();
    const { user, temporaryPassword } = await createUser(root, { upn: "frank@platform.test", name: "Frank", role: "AUDITOR", tenantId: null });
    const change = expectStep(await beginPasswordLogin({ upn: user.upn, password: temporaryPassword }, META, T0), "change-password");
    for (let i = 0; i < MAX_CHALLENGE_ATTEMPTS - 1; i++) expect(await changePasswordStep(change.challengeToken, "short", META, T0)).toMatchObject({ ok: false, restart: false });
    expect(await changePasswordStep(change.challengeToken, "short", META, T0)).toMatchObject({ ok: false, error: RESTART_ERROR, restart: true });
    expect(await changePasswordStep(change.challengeToken, STRONG, META, T0)).toMatchObject({ ok: false, restart: true });
  });

  it("expired challenges and deactivated banks stop the sign-in", async () => {
    const root = await platformAdmin();
    const bank = await createTenant(root, { slug: "bank-b", name: "Bank B", active: true, requireBankApproval: true });
    const { user, temporaryPassword } = await createUser(root, { upn: "dave@bank-b.test", name: "Dave", role: "AUDITOR", tenantId: bank.id });
    const change = expectStep(await beginPasswordLogin({ upn: user.upn, password: temporaryPassword }, META, T0), "change-password");
    expect(await changePasswordStep(change.challengeToken, STRONG, META, at(301))).toMatchObject({ ok: false, restart: true });

    await updateTenant(root, bank.id, { active: false });
    expect(await beginPasswordLogin({ upn: user.upn, password: temporaryPassword }, META, at(400))).toMatchObject({ ok: false, error: LOGIN_ERROR });
  });
});

describe("user administration", () => {
  async function twoBanks() {
    const root = await platformAdmin();
    const a = await createTenant(root, { slug: "bank-a", name: "Bank A", active: true, requireBankApproval: true });
    const b = await createTenant(root, { slug: "bank-b", name: "Bank B", active: true, requireBankApproval: true });
    const adminA = (await createUser(root, { upn: "admin@bank-a.test", name: "Admin A", role: "ADMIN", tenantId: a.id })).user;
    const userB = (await createUser(root, { upn: "user@bank-b.test", name: "User B", role: "AUDITOR", tenantId: b.id })).user;
    return { root, a, b, bankAdmin: asActor(adminA), userB };
  }

  it("nobody from a bank changes any account (403); bank admins and auditors read their own bank's list", async () => {
    const { root, a, b, bankAdmin, userB } = await twoBanks();
    const own = await createUser(root, { upn: "teller@bank-a.test", name: "Teller", role: "AUDITOR", tenantId: a.id });
    const bankAuditor = { ...bankAdmin, role: "AUDITOR" as const };
    const before = await prisma.user.findMany({ orderBy: { upn: "asc" } });

    for (const actor of [bankAdmin, bankAuditor]) {
      // Creating: never, not even in their own bank (a second admin would defeat maker-checker).
      for (const tenantId of [undefined, a.id, null, b.id]) {
        for (const role of ["ADMIN", "AUDITOR"] as const) {
          await expect(createUser(actor, { upn: `n-${role}@bank-a.test`, name: "N", role, tenantId })).rejects.toMatchObject({ status: 403, message: ACCOUNTS_MANAGED_BY_PLATFORM });
        }
      }
      // Editing / resetting / unlocking: never — own bank, other bank, platform, or themselves.
      for (const target of [own.user.id, bankAdmin.id, userB.id, root.id]) {
        for (const change of [{ name: "Renamed" }, { role: "ADMIN" as const }, { role: "AUDITOR" as const }, { active: false }, { active: true }]) {
          await expect(updateUser(actor, target, change)).rejects.toMatchObject({ status: 403 });
        }
        for (const action of ["reset-password", "unlock"] as const) {
          await expect(userAction(actor, target, action)).rejects.toMatchObject({ status: 403, message: ACCOUNTS_MANAGED_BY_PLATFORM });
        }
      }
      // Read-only: their own bank's users only.
      expect((await listUsers(actor)).map((u) => u.upn).sort()).toEqual(["admin@bank-a.test", "teller@bank-a.test"]);
    }
    expect(await prisma.user.findMany({ orderBy: { upn: "asc" } })).toEqual(before); // nothing changed
    await expect(listUsers({ ...bankAdmin, role: "VIEWER" })).rejects.toMatchObject({ status: 403 });

    // Banks are platform-only.
    await expect(createTenant(bankAdmin, { slug: "bank-c", name: "Bank C", active: true, requireBankApproval: true })).rejects.toBeInstanceOf(AuthError);
    await expect(updateTenant(bankAdmin, a.id, { active: false })).rejects.toBeInstanceOf(AuthError);
  });

  it("a platform admin does every account operation for bank users, audited on the bank's chain", async () => {
    const { root, a, bankAdmin } = await twoBanks();
    const created = await createUser(root, { upn: "admin2@bank-a.test", name: "Admin 2", role: "ADMIN", tenantId: a.id });
    expect(created.user.tenantId).toBe(a.id);
    await expect(createUser(root, { upn: "nobank@bank-a.test", name: "No bank", role: "AUDITOR" })).rejects.toBeInstanceOf(DomainError); // bank must be chosen

    await updateUser(root, bankAdmin.id, { name: "Admin A (renamed)" });
    await updateUser(root, bankAdmin.id, { role: "AUDITOR" });
    await updateUser(root, bankAdmin.id, { role: "ADMIN" }); // no cooldown: platform admins decide
    await prisma.user.update({ where: { id: bankAdmin.id }, data: { lockedUntil: new Date(Date.now() + 600_000), failedLogins: 5 } });
    await userAction(root, bankAdmin.id, "unlock");
    expect(await prisma.user.findUniqueOrThrow({ where: { id: bankAdmin.id } })).toMatchObject({ lockedUntil: null, failedLogins: 0 });
    const reset = await userAction(root, bankAdmin.id, "reset-password");
    expect(reset.temporaryPassword).toMatch(/^[A-Za-z2-9]{5}(-[A-Za-z2-9]{5}){3}$/);
    await updateUser(root, bankAdmin.id, { active: false });
    await updateUser(root, bankAdmin.id, { active: true });

    const events = await prisma.auditEvent.findMany({ where: { entity: "User", entityId: { in: [bankAdmin.id, created.user.id] } }, orderBy: { seq: "asc" } });
    expect(events.map((e) => e.action)).toEqual(
      expect.arrayContaining(["user.created", "user.updated", "user.unlocked", "user.password_reset", "user.deactivated", "user.reactivated"]),
    );
    expect(events.every((e) => e.tenantId === a.id && e.actor === root.upn)).toBe(true);
    expect((await verifyAuditLog(a.id)).valid).toBe(true);
  });

  it("nobody can deactivate or demote themselves; the last active platform admin is kept", async () => {
    const root = await platformAdmin();
    await expect(updateUser(root, root.id, { active: false })).rejects.toMatchObject({ status: 409 });
    await expect(updateUser(root, root.id, { role: "AUDITOR" })).rejects.toMatchObject({ status: 409 });

    const second = asActor((await createUser(root, { upn: "second@platform.test", name: "Second", role: "ADMIN", tenantId: null })).user);
    // root demotes second (fine: root remains) …
    await updateUser(root, second.id, { role: "AUDITOR" });
    // … and a concurrent / stale request by `second` must not remove the last platform admin.
    await expect(updateUser(second, root.id, { role: "AUDITOR" })).rejects.toThrow(/At least one active platform administrator/);
    await expect(updateUser(second, root.id, { active: false })).rejects.toThrow(/At least one active platform administrator/);
    expect(await prisma.user.count({ where: { role: "ADMIN", tenantId: null, active: true } })).toBe(1);
  });

  it("password reset and deactivation kill sessions", async () => {
    const root = await platformAdmin();
    const { user, temporaryPassword } = await createUser(root, { upn: "erin@platform.test", name: "Erin", role: "ADMIN", tenantId: null });
    const change = expectStep(await beginPasswordLogin({ upn: user.upn, password: temporaryPassword }, META, T0), "change-password");
    expectStep(await changePasswordStep(change.challengeToken, STRONG, META, T0), "done");
    expect(await prisma.session.count({ where: { userId: user.id } })).toBe(1);

    await userAction(root, user.id, "reset-password");
    expect(await prisma.session.count({ where: { userId: user.id } })).toBe(0);
    expect(await beginPasswordLogin({ upn: user.upn, password: STRONG }, META, at(60))).toMatchObject({ ok: false, error: LOGIN_ERROR });

    await updateUser(root, user.id, { active: false });
    expect(await prisma.authChallenge.count({ where: { userId: user.id } })).toBe(0);
    const actions = await auditActions();
    expect(actions).toContain("user.password_reset");
    expect(actions).toContain("user.deactivated");
  });

  it("refuses duplicate users and bank short codes", async () => {
    const root = await platformAdmin();
    await createTenant(root, { slug: "bank-a", name: "Bank A", active: true, requireBankApproval: true });
    await expect(createTenant(root, { slug: "bank-a", name: "Again", active: true, requireBankApproval: true })).rejects.toMatchObject({ status: 409 });
    await expect(createUser(root, { upn: root.upn, name: "Dup", role: "AUDITOR", tenantId: null })).rejects.toMatchObject({ status: 409 });
  });
});
