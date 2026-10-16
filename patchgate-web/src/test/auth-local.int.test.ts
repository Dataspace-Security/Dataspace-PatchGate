/**
 * Local sign-in (password + TOTP) and user/bank administration against a real PostgreSQL.
 * Run: TEST_DATABASE_URL=postgresql://…/patchgate_test_auth npm run test:int -- src/test/auth-local.int.test.ts
 */
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { configureTestEnv, resetDb } from "./helpers";

configureTestEnv({ AUTH_MODE: "local", AUTH_ENC_KEY: "ab".repeat(32) });

const { prisma } = await import("@/lib/db");
const { beginPasswordLogin, verifyTotpStep, changePasswordStep, LOGIN_ERROR, CODE_ERROR, RESTART_ERROR } = await import("@/lib/auth/local-login");
const { createUser, updateUser, userAction, createTenant, updateTenant, listUsers } = await import("@/lib/auth/admin-service");
const { hashPassword } = await import("@/lib/auth/password");
const { base32Decode, hotp, totpStep } = await import("@/lib/auth/totp");
const { sha256Hex } = await import("@/lib/auth/tokens");
const { AuthError } = await import("@/lib/auth/session");
const { DomainError } = await import("@/lib/errors");
type SessionUser = import("@/lib/auth/session").SessionUser;
type LoginStep = import("@/lib/auth/local-login").LoginStep;

const META = { ip: "10.0.0.1", userAgent: "vitest" };
const T0 = new Date("2026-10-15T09:00:00Z");
const at = (seconds: number) => new Date(T0.getTime() + seconds * 1000);
const codeFor = (secret: string, when: Date) => hotp(base32Decode(secret), totpStep(when.getTime()));
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

/** Sign in from scratch for a user who already has TOTP; returns the session token. */
async function fullLogin(upn: string, password: string, secret: string, when: Date): Promise<string> {
  const p = expectStep(await beginPasswordLogin({ upn, password }, META, when), "verify");
  const done = expectStep(await verifyTotpStep(p.challengeToken, codeFor(secret, when), META, when), "done");
  return done.sessionToken;
}

beforeEach(resetAll);
afterAll(() => prisma.$disconnect());

describe("local sign-in", () => {
  it("temporary password → TOTP enrolment → forced password change → session; then normal sign-in", async () => {
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

    const enrol = expectStep(await beginPasswordLogin({ upn: "alice@bank-a.test", password: temporaryPassword, returnTo: "/change-requests" }, META, T0), "enroll");
    expect(enrol.otpauthUri).toMatch(/^otpauth:\/\/totp\/PatchGate:alice%40bank-a\.test\?secret=/);
    expect(enrol.qrSvgDataUrl).toMatch(/^data:image\/svg\+xml;base64,/);
    const pending = await prisma.authChallenge.findUniqueOrThrow({ where: { id: sha256Hex(enrol.challengeToken) } });
    expect(pending.kind).toBe("ENROLL");
    expect(pending.pendingSecretEnc).toMatch(/^v1\./);
    expect(pending.pendingSecretEnc).not.toContain(enrol.secret.replace(/ /g, ""));

    const change = expectStep(await verifyTotpStep(enrol.challengeToken, codeFor(enrol.secret, T0), META, T0), "change-password");
    // The enrolment challenge is single use.
    expect((await verifyTotpStep(enrol.challengeToken, codeFor(enrol.secret, at(30)), META, at(30))).ok).toBe(false);
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
    expect(after).toMatchObject({ mustChangePassword: false, totpEnabled: true, failedLogins: 0 });
    expect(await prisma.authChallenge.count()).toBe(0);

    // Old temporary password no longer works; the new one + TOTP does.
    expect(await beginPasswordLogin({ upn: "alice@bank-a.test", password: temporaryPassword }, META, at(60))).toMatchObject({ ok: false, error: LOGIN_ERROR });
    await fullLogin("alice@bank-a.test", STRONG, enrol.secret, at(90));

    const actions = await auditActions();
    for (const a of ["tenant.created", "user.created", "auth.mfa_enrolled", "auth.password_changed", "auth.login", "auth.failed"]) expect(actions).toContain(a);
    const loginEvent = await prisma.auditEvent.findFirstOrThrow({ where: { action: "auth.login" } });
    expect(loginEvent.tenantId).toBe(bank.id); // bank user → bank's audit chain
  });

  it("rejects a replayed TOTP code (each 30-s step is usable once)", async () => {
    const root = await platformAdmin();
    const { user, temporaryPassword } = await createUser(root, { upn: "bob@platform.test", name: "Bob", role: "ADMIN", tenantId: null });
    const enrol = expectStep(await beginPasswordLogin({ upn: user.upn, password: temporaryPassword }, META, T0), "enroll");
    const change = expectStep(await verifyTotpStep(enrol.challengeToken, codeFor(enrol.secret, T0), META, T0), "change-password");
    expectStep(await changePasswordStep(change.challengeToken, STRONG, META, T0), "done");

    // Same code, a few seconds later, in a fresh sign-in: refused.
    const again = expectStep(await beginPasswordLogin({ upn: user.upn, password: STRONG }, META, at(5)), "verify");
    expect(await verifyTotpStep(again.challengeToken, codeFor(enrol.secret, T0), META, at(5))).toMatchObject({ ok: false, error: CODE_ERROR });
    expect((await prisma.user.findUniqueOrThrow({ where: { id: user.id } })).failedLogins).toBe(1);
    // The next step's code is accepted.
    expectStep(await verifyTotpStep(again.challengeToken, codeFor(enrol.secret, at(30)), META, at(30)), "done");
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

    // Correct password while locked: same generic refusal, no challenge issued.
    expect(await beginPasswordLogin({ upn: root.upn, password: STRONG }, META, at(60))).toMatchObject({ ok: false, error: LOGIN_ERROR });
    expect(await prisma.authChallenge.count()).toBe(0);
    // After the lock expires, sign-in proceeds to the second factor.
    expectStep(await beginPasswordLogin({ upn: root.upn, password: STRONG }, META, at(16 * 60)), "enroll");
  });

  it("wrong TOTP codes burn the challenge after 5 attempts and count towards lockout", async () => {
    const root = await platformAdmin();
    const enrol = expectStep(await beginPasswordLogin({ upn: root.upn, password: STRONG }, META, T0), "enroll");
    const good = codeFor(enrol.secret, T0);
    const bad = good === "000000" ? "111111" : "000000";
    for (let i = 0; i < 4; i++) expect(await verifyTotpStep(enrol.challengeToken, bad, META, T0)).toMatchObject({ ok: false, error: CODE_ERROR });
    expect(await verifyTotpStep(enrol.challengeToken, bad, META, T0)).toMatchObject({ ok: false, error: RESTART_ERROR, restart: true });
    expect(await verifyTotpStep(enrol.challengeToken, good, META, T0)).toMatchObject({ ok: false, restart: true });
    expect((await prisma.user.findUniqueOrThrow({ where: { id: root.id } })).lockedUntil).not.toBeNull();
  });

  it("expired challenges and deactivated banks stop the sign-in", async () => {
    const root = await platformAdmin();
    const bank = await createTenant(root, { slug: "bank-b", name: "Bank B", active: true, requireBankApproval: true });
    const { user, temporaryPassword } = await createUser(root, { upn: "dave@bank-b.test", name: "Dave", role: "AUDITOR", tenantId: bank.id });
    const enrol = expectStep(await beginPasswordLogin({ upn: user.upn, password: temporaryPassword }, META, T0), "enroll");
    expect(await verifyTotpStep(enrol.challengeToken, codeFor(enrol.secret, at(301)), META, at(301))).toMatchObject({ ok: false, restart: true });

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

  it("a bank admin manages only their own bank's users", async () => {
    const { root, a, b, bankAdmin, userB } = await twoBanks();

    // Creating: forced into their own bank; never a platform user or another bank's user.
    const own = await createUser(bankAdmin, { upn: "teller@bank-a.test", name: "Teller", role: "AUDITOR" });
    expect(own.user.tenantId).toBe(a.id);
    await expect(createUser(bankAdmin, { upn: "x@platform.test", name: "X", role: "ADMIN", tenantId: null })).rejects.toBeInstanceOf(AuthError);
    await expect(createUser(bankAdmin, { upn: "y@bank-b.test", name: "Y", role: "AUDITOR", tenantId: b.id })).rejects.toBeInstanceOf(AuthError);

    // Other bank / platform users are invisible and untouchable.
    for (const target of [userB.id, root.id]) {
      await expect(updateUser(bankAdmin, target, { active: false })).rejects.toMatchObject({ status: 404 });
      await expect(userAction(bankAdmin, target, "reset-password")).rejects.toBeInstanceOf(DomainError);
      await expect(userAction(bankAdmin, target, "reset-mfa")).rejects.toMatchObject({ status: 404 });
    }
    const visible = await listUsers(bankAdmin);
    expect(visible.map((u) => u.upn).sort()).toEqual(["admin@bank-a.test", "teller@bank-a.test"]);

    // Banks are platform-only.
    await expect(createTenant(bankAdmin, { slug: "bank-c", name: "Bank C", active: true, requireBankApproval: true })).rejects.toBeInstanceOf(AuthError);
    await expect(updateTenant(bankAdmin, a.id, { active: false })).rejects.toBeInstanceOf(AuthError);

    // Auditors see their bank's users (read-only) but cannot administer; retired roles see nothing.
    expect((await listUsers({ ...bankAdmin, role: "AUDITOR" })).map((u) => u.upn).sort()).toEqual(["admin@bank-a.test", "teller@bank-a.test"]);
    await expect(createUser({ ...bankAdmin, role: "AUDITOR" }, { upn: "z@bank-a.test", name: "Z", role: "AUDITOR" })).rejects.toMatchObject({ status: 403 });
    await expect(userAction({ ...bankAdmin, role: "AUDITOR" }, own.user.id, "reset-password")).rejects.toMatchObject({ status: 403 });
    await expect(listUsers({ ...bankAdmin, role: "VIEWER" })).rejects.toMatchObject({ status: 403 });

    // In-bank management works and is audited on the bank's chain.
    const reset = await userAction(bankAdmin, own.user.id, "reset-password");
    expect(reset.temporaryPassword).toMatch(/^[A-Za-z2-9]{5}(-[A-Za-z2-9]{5}){3}$/);
    const ev = await prisma.auditEvent.findFirstOrThrow({ where: { action: "user.password_reset" } });
    expect(ev.tenantId).toBe(a.id);
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

  it("deactivation kills sessions; MFA reset forces re-enrolment", async () => {
    const root = await platformAdmin();
    const { user, temporaryPassword } = await createUser(root, { upn: "erin@platform.test", name: "Erin", role: "ADMIN", tenantId: null });
    const enrol = expectStep(await beginPasswordLogin({ upn: user.upn, password: temporaryPassword }, META, T0), "enroll");
    const change = expectStep(await verifyTotpStep(enrol.challengeToken, codeFor(enrol.secret, T0), META, T0), "change-password");
    expectStep(await changePasswordStep(change.challengeToken, STRONG, META, T0), "done");
    expect(await prisma.session.count({ where: { userId: user.id } })).toBe(1);

    await userAction(root, user.id, "reset-mfa");
    expect(await prisma.session.count({ where: { userId: user.id } })).toBe(0);
    expectStep(await beginPasswordLogin({ upn: user.upn, password: STRONG }, META, at(60)), "enroll");

    await updateUser(root, user.id, { active: false });
    expect(await prisma.authChallenge.count({ where: { userId: user.id } })).toBe(0);
    const actions = await auditActions();
    expect(actions).toContain("user.mfa_reset");
    expect(actions).toContain("user.deactivated");
  });

  it("refuses duplicate users and bank short codes", async () => {
    const root = await platformAdmin();
    await createTenant(root, { slug: "bank-a", name: "Bank A", active: true, requireBankApproval: true });
    await expect(createTenant(root, { slug: "bank-a", name: "Again", active: true, requireBankApproval: true })).rejects.toMatchObject({ status: 409 });
    await expect(createUser(root, { upn: root.upn, name: "Dup", role: "AUDITOR", tenantId: null })).rejects.toMatchObject({ status: 409 });
  });
});
