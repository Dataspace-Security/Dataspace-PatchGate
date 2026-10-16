/**
 * Platform account security policies against a real PostgreSQL: password max age forces a change at the
 * next sign-in, inactivity auto-disable (keeps one platform admin), max concurrent sessions per user.
 * Run: TEST_DATABASE_URL=postgresql://…/patchgate_test_auth INTEGRATION=1 npx vitest run src/test/account-policy.int.test.ts
 */
import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";
import { TENANT_A, asSessionUser, configureTestEnv, resetDb } from "./helpers";

configureTestEnv({ AUTH_MODE: "local", AUTH_ENC_KEY: "ab".repeat(32) });
vi.setConfig({ testTimeout: 300_000, hookTimeout: 120_000 });

const { prisma } = await import("@/lib/db");
const { beginPasswordLogin, verifyTotpStep, changePasswordStep } = await import("@/lib/auth/local-login");
const { hashPassword } = await import("@/lib/auth/password");
const { base32Decode, hotp, totpStep } = await import("@/lib/auth/totp");
const { updateUser } = await import("@/lib/auth/admin-service");
const { updateSecurityPolicy, getSecurityPolicy } = await import("@/lib/policies/security-store");
const { disableInactiveUsers } = await import("@/lib/policies/inactivity");
const { withPlatform } = await import("@/lib/tenancy");
type LoginStep = import("@/lib/auth/local-login").LoginStep;

const META = { ip: "10.0.0.9", userAgent: "vitest" };
const STRONG = "orbit-Kettle-7-sandstone-river";
const NEW_PW = "lantern-Quartz-9-meadow-falcon";
const DAY = 86_400_000;
const NOW = new Date();
const at = (seconds: number) => new Date(NOW.getTime() + seconds * 1000);
const codeFor = (secret: string, when: Date) => hotp(base32Decode(secret.replace(/\s+/g, "")), totpStep(when.getTime()));

function step<S extends Extract<LoginStep, { ok: true }>["step"]>(r: LoginStep, s: S): Extract<LoginStep, { step: S }> {
  if (!r.ok) throw new Error(`expected ${s}, got error: ${r.error}`);
  expect(r.step).toBe(s);
  return r as Extract<LoginStep, { step: S }>;
}

async function resetAll() {
  await prisma.$executeRawUnsafe(`DELETE FROM "ChangeRequestApproval"`);
  await prisma.$executeRawUnsafe(`DELETE FROM "SecurityPolicy"`);
  await resetDb(prisma);
}

/** Enrol TOTP through the real flow; returns the base32 secret (the user ends signed in once). */
async function enrol(upn: string, when: Date): Promise<string> {
  const e = step(await beginPasswordLogin({ upn, password: STRONG }, META, when), "enroll");
  step(await verifyTotpStep(e.challengeToken, codeFor(e.secret, when), META, when), "done");
  return e.secret;
}

async function login(upn: string, secret: string, when: Date): Promise<LoginStep> {
  const v = step(await beginPasswordLogin({ upn, password: STRONG }, META, when), "verify");
  return verifyTotpStep(v.challengeToken, codeFor(secret, when), META, when);
}

async function platformAdmin(upn = "root@platform.test", extra: { createdAt?: Date; lastLoginAt?: Date | null } = {}) {
  return asSessionUser(await prisma.user.create({ data: { upn, name: upn, role: "ADMIN", passwordHash: await hashPassword(STRONG), ...extra } }));
}

async function audit(action: string, tenantId: string | null = null) {
  return withPlatform((tx) => tx.auditEvent.findMany({ where: { action, tenantId }, orderBy: { seq: "asc" } }));
}

beforeEach(resetAll);
afterAll(async () => {
  await prisma.$executeRawUnsafe(`DELETE FROM "SecurityPolicy"`);
  await prisma.$disconnect();
});

describe("security policy administration", () => {
  it("platform admins only; audited on the platform chain", async () => {
    const root = await platformAdmin();
    const bankAdmin = asSessionUser(await prisma.user.create({ data: { upn: "admin@bank-a.test", name: "Bank admin", role: "ADMIN", tenantId: TENANT_A } }));
    await expect(updateSecurityPolicy(bankAdmin, { maxSessionsPerUser: 1 })).rejects.toThrow(/platform administrators only/i);
    await expect(updateSecurityPolicy(root, { inactivityDisableDays: 2 })).rejects.toThrow();
    await updateSecurityPolicy(root, { passwordMaxAgeDays: 60, maxSessionsPerUser: 3 });
    expect(await getSecurityPolicy()).toEqual({ passwordMaxAgeDays: 60, inactivityDisableDays: 90, maxSessionsPerUser: 3 });
    const [ev] = await audit("security_policy.updated");
    expect(ev?.payload).toMatchObject({ changes: { passwordMaxAgeDays: { from: 0, to: 60 }, maxSessionsPerUser: { from: 0, to: 3 } } });
  });
});

describe("password max age", () => {
  it("an expired password forces a change at the next sign-in, then signs in normally", async () => {
    const root = await platformAdmin();
    const u = await prisma.user.create({ data: { upn: "alice@bank-a.test", name: "Alice", role: "OPERATOR", tenantId: TENANT_A, passwordHash: await hashPassword(STRONG) } });
    const secret = await enrol(u.upn, at(0));

    await updateSecurityPolicy(root, { passwordMaxAgeDays: 30 });
    step(await login(u.upn, secret, at(60)), "done"); // fresh password: no change needed

    await prisma.user.update({ where: { id: u.id }, data: { passwordChangedAt: new Date(NOW.getTime() - 31 * DAY) } });
    const forced = step(await login(u.upn, secret, at(120)), "change-password");
    expect((await audit("auth.password_expired", TENANT_A)).length).toBe(1);
    step(await changePasswordStep(forced.challengeToken, NEW_PW, META, at(121)), "done");
    const after = await prisma.user.findUniqueOrThrow({ where: { id: u.id } });
    expect(after.passwordChangedAt!.getTime()).toBeGreaterThan(NOW.getTime() - DAY);
    // policy off again → never forced
    await updateSecurityPolicy(root, { passwordMaxAgeDays: 0 });
    await prisma.user.update({ where: { id: u.id }, data: { passwordChangedAt: new Date(NOW.getTime() - 400 * DAY) } });
    const v = step(await beginPasswordLogin({ upn: u.upn, password: NEW_PW }, META, at(180)), "verify");
    step(await verifyTotpStep(v.challengeToken, codeFor(secret, at(180)), META, at(180)), "done");
  });
});

describe("max concurrent sessions", () => {
  it("a new sign-in revokes the oldest sessions beyond the cap (audited)", async () => {
    const root = await platformAdmin();
    const u = await prisma.user.create({ data: { upn: "bob@bank-a.test", name: "Bob", role: "APPROVER", tenantId: TENANT_A, passwordHash: await hashPassword(STRONG) } });
    const secret = await enrol(u.upn, at(0)); // session #1
    await updateSecurityPolicy(root, { maxSessionsPerUser: 2 });
    step(await login(u.upn, secret, at(60)), "done"); // #2
    expect(await prisma.session.count({ where: { userId: u.id } })).toBe(2);
    const first = await prisma.session.findFirstOrThrow({ where: { userId: u.id }, orderBy: { createdAt: "asc" } });
    const third = step(await login(u.upn, secret, at(120)), "done"); // #3 → #1 revoked
    const left = await prisma.session.findMany({ where: { userId: u.id } });
    expect(left).toHaveLength(2);
    expect(left.map((s) => s.id)).not.toContain(first.id);
    expect(third.sessionToken).toBeTruthy();
    const [ev] = await audit("auth.sessions_revoked", TENANT_A);
    expect(ev?.payload).toMatchObject({ reason: "session_cap", revoked: 1, maxSessionsPerUser: 2 });

    await updateSecurityPolicy(root, { maxSessionsPerUser: 1 });
    step(await login(u.upn, secret, at(180)), "done");
    expect(await prisma.session.count({ where: { userId: u.id } })).toBe(1);
  });
});

describe("inactivity auto-disable", () => {
  it("deactivates inactive users (sessions revoked, audited), skips recently administered ones, keeps one platform admin", async () => {
    const long = new Date(NOW.getTime() - 200 * DAY);
    const rootOld = await platformAdmin("root-old@platform.test", { createdAt: long, lastLoginAt: new Date(NOW.getTime() - 150 * DAY) });
    const rootOlder = await platformAdmin("root-older@platform.test", { createdAt: long, lastLoginAt: null });
    const idle = await prisma.user.create({ data: { upn: "idle@bank-a.test", name: "Idle", role: "OPERATOR", tenantId: TENANT_A, createdAt: long, lastLoginAt: long } });
    const active = await prisma.user.create({ data: { upn: "busy@bank-a.test", name: "Busy", role: "OPERATOR", tenantId: TENANT_A, createdAt: long, lastLoginAt: new Date(NOW.getTime() - DAY) } });
    const fresh = await prisma.user.create({ data: { upn: "new@bank-a.test", name: "New", role: "VIEWER", tenantId: TENANT_A } });
    await prisma.session.create({ data: { id: "s".repeat(64), userId: idle.id, createdAt: long, lastSeenAt: long, expiresAt: new Date(NOW.getTime() + DAY) } });

    const r = await disableInactiveUsers(NOW);
    expect(r.disabled).toBe(2); // idle + the less recently active platform admin
    const state = Object.fromEntries((await prisma.user.findMany({ select: { upn: true, active: true } })).map((u) => [u.upn, u.active]));
    expect(state).toMatchObject({ [idle.upn]: false, [rootOlder.upn]: false, [rootOld.upn]: true, [active.upn]: true, [fresh.upn]: true });
    expect(await prisma.session.count({ where: { userId: idle.id } })).toBe(0);
    expect((await audit("user.deactivated_inactive", TENANT_A)).map((e) => e.entityId)).toEqual([idle.id]);
    expect((await audit("user.deactivated_inactive", null)).map((e) => e.entityId)).toEqual([rootOlder.id]);

    // Running again changes nothing: the last platform admin is never disabled
    expect((await disableInactiveUsers(NOW)).disabled).toBe(0);

    // A reactivation by an administrator restarts the clock (user.reactivated is administrator activity)
    await updateUser(rootOld, idle.id, { active: true });
    expect((await disableInactiveUsers(NOW)).disabled).toBe(0);
    expect((await prisma.user.findUniqueOrThrow({ where: { id: idle.id } })).active).toBe(true);

    // Policy off → nothing happens
    await updateSecurityPolicy(rootOld, { inactivityDisableDays: 0 });
    await prisma.user.update({ where: { id: active.id }, data: { lastLoginAt: long } });
    expect((await disableInactiveUsers(NOW)).disabled).toBe(0);
  });
});
