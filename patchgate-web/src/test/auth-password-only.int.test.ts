/**
 * Local sign-in is PASSWORD-ONLY by design (TOTP removed, migration 20261016170000_remove_totp): no second
 * step, no authenticator columns in the database; temporary-password change, lockout and session rules still
 * apply. Banks that need MFA use their SSO (AUTH_MODE=oidc), where the IdP enforces it.
 * Run: TEST_DATABASE_URL=postgresql://…/patchgate_test_auth INTEGRATION=1 npx vitest run src/test/auth-password-only.int.test.ts
 */
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { configureTestEnv, resetDb } from "./helpers";

configureTestEnv({ AUTH_MODE: "local", AUTH_ENC_KEY: "ab".repeat(32) });

const { prisma } = await import("@/lib/db");
const localLogin = await import("@/lib/auth/local-login");
const { beginPasswordLogin, changePasswordStep, LOGIN_ERROR, LOCAL_LOGIN_METHOD } = localLogin;
const { createUser, createTenant, userActionSchema } = await import("@/lib/auth/admin-service");
const { hashPassword } = await import("@/lib/auth/password");
const { readiness } = await import("@/lib/health");
type LoginStep = import("@/lib/auth/local-login").LoginStep;
type SessionUser = import("@/lib/auth/session").SessionUser;

const META = { ip: "10.0.0.9", userAgent: "vitest" };
const STRONG = "orbit-Kettle-7-sandstone-river";
const STRONG2 = "quartz-Lantern-9-meadow-falcon";

function expectStep<S extends Extract<LoginStep, { ok: true }>["step"]>(r: LoginStep, step: S): Extract<LoginStep, { step: S }> {
  if (!r.ok) throw new Error(`expected ${step}, got error: ${r.error}`);
  expect(r.step).toBe(step);
  return r as Extract<LoginStep, { step: S }>;
}

beforeEach(async () => {
  await resetDb(prisma);
  await prisma.$executeRawUnsafe(`TRUNCATE "AuthChallenge", "Session", "Tenant" CASCADE`);
});
afterAll(() => prisma.$disconnect());

async function root(): Promise<SessionUser> {
  const u = await prisma.user.create({ data: { upn: "root@platform.test", name: "Root", role: "ADMIN", passwordHash: await hashPassword(STRONG) } });
  return { id: u.id, role: u.role, upn: u.upn, name: u.name, tenantId: null };
}

describe("password-only local sign-in", () => {
  it("the right password → session at once; recorded as method=password; no pending step", async () => {
    const admin = await root();
    const r = expectStep(await beginPasswordLogin({ upn: admin.upn, password: STRONG, returnTo: "/patches" }, META), "done");
    expect(r.returnTo).toBe("/patches");
    expect(await prisma.session.count({ where: { userId: admin.id } })).toBe(1);
    expect(await prisma.authChallenge.count()).toBe(0);
    const login = await prisma.auditEvent.findFirstOrThrow({ where: { action: "auth.login", entityId: admin.id } });
    expect(LOCAL_LOGIN_METHOD).toBe("password");
    expect(login.payload).toMatchObject({ method: "password" });
  });

  it("exposes no TOTP step, no MFA reset action and no MFA readiness check", async () => {
    expect(Object.keys(localLogin).filter((k) => /totp|mfa|enrol/i.test(k))).toEqual([]);
    expect(userActionSchema.safeParse({ action: "reset-mfa" }).success).toBe(false);
    expect(userActionSchema.shape.action.options).toEqual(["reset-password", "unlock"]);
    expect((await readiness()).checks).not.toHaveProperty("mfa");
  });

  it("the database has no authenticator columns and only password-change challenges", async () => {
    const cols = await prisma.$queryRaw<{ table_name: string; column_name: string }[]>`
      SELECT table_name, column_name FROM information_schema.columns
      WHERE table_schema = current_schema() AND table_name IN ('User', 'AuthChallenge')`;
    const names = cols.map((c) => `${c.table_name}.${c.column_name}`);
    expect(names).toContain("User.passwordHash");
    expect(names.filter((n) => /totp|pendingSecret/i.test(n))).toEqual([]);
  });

  it("a temporary password must still be changed before the session is issued", async () => {
    const admin = await root();
    const bank = await createTenant(admin, { slug: "bank-a", name: "Bank A", active: true, requireBankApproval: true });
    const { user, temporaryPassword } = await createUser(admin, { upn: "aud@bank-a.test", name: "Aud", role: "AUDITOR", tenantId: bank.id });
    const ch = expectStep(await beginPasswordLogin({ upn: user.upn, password: temporaryPassword }, META), "change-password");
    expect(await prisma.session.count({ where: { userId: user.id } })).toBe(0);
    expectStep(await changePasswordStep(ch.challengeToken, STRONG2, META), "done");
    const u = await prisma.user.findUniqueOrThrow({ where: { id: user.id } });
    expect(u.mustChangePassword).toBe(false);
    expect(await prisma.session.count({ where: { userId: user.id } })).toBe(1);
  });

  it("lockout still applies: 5 wrong passwords lock the account, even the right one is refused", async () => {
    const admin = await root();
    for (let i = 0; i < 5; i++) {
      const r = await beginPasswordLogin({ upn: admin.upn, password: "wrong-password-xx" }, META);
      expect(r).toMatchObject({ ok: false, error: LOGIN_ERROR });
    }
    expect((await prisma.user.findUniqueOrThrow({ where: { id: admin.id } })).lockedUntil).not.toBeNull();
    expect(await beginPasswordLogin({ upn: admin.upn, password: STRONG }, META)).toMatchObject({ ok: false });
    expect(await prisma.auditEvent.count({ where: { action: "auth.lockout" } })).toBe(1);
  });
});
