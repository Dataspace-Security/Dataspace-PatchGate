/**
 * AUTH_MFA=off: local sign-in is password only (no TOTP step, no forced enrolment); stored TOTP secrets are
 * untouched; temporary-password change, lockout and session rules still apply; one `auth.mfa_disabled`
 * event per process on the platform chain. (AUTH_MFA=required keeps the TOTP step: auth-local.int.test.ts.)
 * Run: TEST_DATABASE_URL=postgresql://…/patchgate_test_auth INTEGRATION=1 npx vitest run src/test/auth-mfa-off.int.test.ts
 */
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { configureTestEnv, resetDb } from "./helpers";

configureTestEnv({ AUTH_MODE: "local", AUTH_MFA: "off", AUTH_ENC_KEY: "ab".repeat(32) });

const { prisma } = await import("@/lib/db");
const { beginPasswordLogin, verifyTotpStep, changePasswordStep, LOGIN_ERROR } = await import("@/lib/auth/local-login");
const { createUser, createTenant } = await import("@/lib/auth/admin-service");
const { hashPassword } = await import("@/lib/auth/password");
const { encryptSecret } = await import("@/lib/auth/secret-box");
const { announceMfaDisabledOnce, MFA_DISABLED_ACTION } = await import("@/lib/auth/mfa-status");
const { mfaDisabled, mfaRequired } = await import("@/lib/env");
const { readiness } = await import("@/lib/health");
const { verifyAuditLog } = await import("@/lib/audit/service");
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

describe("AUTH_MFA=off", () => {
  it("is reported as off (env helpers, readiness)", async () => {
    expect(mfaRequired()).toBe(false);
    expect(mfaDisabled()).toBe(true);
    expect((await readiness()).checks.mfa).toBe(false);
  });

  it("password only → session; the login is recorded as method=password; no authenticator is enrolled", async () => {
    const admin = await root();
    const r = expectStep(await beginPasswordLogin({ upn: admin.upn, password: STRONG, returnTo: "/patches" }, META), "done");
    expect(r.returnTo).toBe("/patches");
    expect(await prisma.session.count({ where: { userId: admin.id } })).toBe(1);
    const login = await prisma.auditEvent.findFirstOrThrow({ where: { action: "auth.login", entityId: admin.id } });
    expect(login.payload).toMatchObject({ method: "password" });
    const u = await prisma.user.findUniqueOrThrow({ where: { id: admin.id } });
    expect([u.totpEnabled, u.totpSecretEnc]).toEqual([false, null]);
    expect(await prisma.authChallenge.count()).toBe(0);
  });

  it("keeps an existing TOTP secret untouched (switching back to required works at once)", async () => {
    const admin = await root();
    const secretEnc = encryptSecret(Buffer.alloc(20, 7), "ab".repeat(32), admin.id);
    await prisma.user.update({ where: { id: admin.id }, data: { totpSecretEnc: secretEnc, totpEnabled: true, totpLastStep: 42 } });
    expectStep(await beginPasswordLogin({ upn: admin.upn, password: STRONG }, META), "done");
    const u = await prisma.user.findUniqueOrThrow({ where: { id: admin.id } });
    expect([u.totpSecretEnc, u.totpEnabled, u.totpLastStep]).toEqual([secretEnc, true, 42]);
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
    // the TOTP endpoint has nothing to verify while MFA is off
    const totp = await verifyTotpStep(ch.challengeToken, "123456", META);
    expect(totp.ok).toBe(false);
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

  it("writes auth.mfa_disabled ONCE per process on the platform chain", async () => {
    const results = await Promise.all([announceMfaDisabledOnce(), announceMfaDisabledOnce()]);
    expect(await announceMfaDisabledOnce()).toBe(false);
    const events = await prisma.auditEvent.findMany({ where: { action: MFA_DISABLED_ACTION } });
    // resetDb above ran before; earlier tests in this file never announced
    expect(results.filter(Boolean)).toHaveLength(1);
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({ tenantId: null, actor: "system:config", entity: "Config", entityId: "AUTH_MFA" });
    expect((await verifyAuditLog(null)).valid).toBe(true);
  });
});
