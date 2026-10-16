/**
 * Self-service account actions (/account) against a real PostgreSQL.
 * Run: TEST_DATABASE_URL=postgresql://…/patchgate_test_auth npm run test:int -- src/test/account.int.test.ts
 */
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { configureTestEnv, resetDb, TENANT_B } from "./helpers";

configureTestEnv({ AUTH_MODE: "local", AUTH_ENC_KEY: "ab".repeat(32) });

const { prisma } = await import("@/lib/db");
const { changeOwnPassword, revokeOtherSessions, getAccountOverview, WRONG_CURRENT, LOCKED_OUT, ACCOUNT_LOCKED } = await import("@/lib/auth/account-service");
const { hashPassword, verifyPassword } = await import("@/lib/auth/password");
const { createSession } = await import("@/lib/auth/session-store");
const { sha256Hex } = await import("@/lib/auth/tokens");
const { beginPasswordLogin } = await import("@/lib/auth/local-login");
const { MAX_FAILED_LOGINS } = await import("@/lib/auth/lockout");

const META = { ip: "10.0.0.9", userAgent: "vitest" };
const T0 = new Date("2026-10-16T09:00:00Z");
const STRONG = "orbit-Kettle-7-sandstone-river";
const NEXT = "harbour-Lantern-4-meadow-quartz";

interface Fixture {
  userId: string;
  current: string; // session id (sha256 of the cookie token)
  others: string[];
}

async function seedUser(tenantId: string | null, upn = "alice@bank-b.test"): Promise<Fixture> {
  const u = await prisma.user.create({
    data: { upn, name: "Alice", role: "ADMIN", tenantId, passwordHash: await hashPassword(STRONG), lastLoginAt: T0 },
  });
  const tokens = await prisma.$transaction(async (tx) => {
    const out: string[] = [];
    for (let i = 0; i < 3; i++) out.push(await createSession(tx, { userId: u.id, now: T0, meta: META }));
    return out;
  });
  const ids = tokens.map(sha256Hex);
  return { userId: u.id, current: ids[0], others: ids.slice(1) };
}

const ctxOf = (f: Fixture) => ({ userId: f.userId, sessionId: f.current });
const change = (f: Fixture, currentPassword: string, newPassword: string, confirmPassword = newPassword) =>
  changeOwnPassword(ctxOf(f), { currentPassword, newPassword, confirmPassword }, META, T0);
const auditOf = (action: string) => prisma.auditEvent.findMany({ where: { action }, orderBy: { seq: "asc" } });

beforeEach(async () => {
  await resetDb(prisma);
});
afterAll(() => prisma.$disconnect());

describe("self-service password change", () => {
  it("rejects a wrong current password and counts it toward the lockout", async () => {
    const f = await seedUser(TENANT_B);
    const r = await change(f, "not-my-password-at-all", NEXT);
    expect(r).toEqual({ ok: false, status: 400, error: WRONG_CURRENT, signedOut: false });
    const u = await prisma.user.findUniqueOrThrow({ where: { id: f.userId } });
    expect(u.failedLogins).toBe(1);
    expect(await verifyPassword(STRONG, u.passwordHash ?? "")).toBe(true);
    const failed = await auditOf("auth.failed");
    expect(failed).toHaveLength(1);
    expect(failed[0].tenantId).toBe(TENANT_B);
    expect(await prisma.session.count({ where: { userId: f.userId } })).toBe(3);
  });

  it("locks the account after the 5th wrong current password and signs the user out everywhere", async () => {
    const f = await seedUser(null, "ops@platform.test");
    for (let i = 1; i < MAX_FAILED_LOGINS; i++) expect(await change(f, `wrong-password-${i}-xyz`, NEXT)).toMatchObject({ ok: false, status: 400 });
    const last = await change(f, "wrong-password-5-xyz", NEXT);
    expect(last).toEqual({ ok: false, status: 401, error: LOCKED_OUT, signedOut: true });
    expect(await prisma.session.count({ where: { userId: f.userId } })).toBe(0);
    expect((await prisma.user.findUniqueOrThrow({ where: { id: f.userId } })).lockedUntil?.getTime()).toBeGreaterThan(T0.getTime());
    expect(await auditOf("auth.lockout")).toHaveLength(1);
    // The lock applies to sign-in as well (shared counter / lock).
    expect(await beginPasswordLogin({ upn: "ops@platform.test", password: STRONG }, META, T0)).toMatchObject({ ok: false });
  });

  it("refuses while the account is locked, even with the right password", async () => {
    const f = await seedUser(TENANT_B);
    await prisma.user.update({ where: { id: f.userId }, data: { lockedUntil: new Date(T0.getTime() + 60_000) } });
    expect(await change(f, STRONG, NEXT)).toMatchObject({ ok: false, status: 403, error: ACCOUNT_LOCKED });
  });

  it("enforces the password policy, the confirmation and new ≠ old", async () => {
    const f = await seedUser(TENANT_B);
    expect(await change(f, STRONG, "short-pass")).toMatchObject({ ok: false, status: 400, error: expect.stringMatching(/at least 14/) });
    expect(await change(f, STRONG, "Password12345678")).toMatchObject({ ok: false, status: 400, error: expect.stringMatching(/common/) });
    expect(await change(f, STRONG, "alice-and-more-words-1")).toMatchObject({ ok: false, error: expect.stringMatching(/username/) });
    expect(await change(f, STRONG, NEXT, `${NEXT}!`)).toMatchObject({ ok: false, error: expect.stringMatching(/do not match/) });
    expect(await change(f, STRONG, STRONG)).toMatchObject({ ok: false, error: expect.stringMatching(/different/) });
    const u = await prisma.user.findUniqueOrThrow({ where: { id: f.userId } });
    expect(u.failedLogins).toBe(0); // policy problems are not authentication failures
    expect(await auditOf("auth.password_changed")).toHaveLength(0);
  });

  it("changes the password, revokes all OTHER sessions, keeps the current one and audits on the bank chain", async () => {
    const f = await seedUser(TENANT_B);
    await prisma.user.update({ where: { id: f.userId }, data: { mustChangePassword: true, failedLogins: 2 } });
    await prisma.authChallenge.create({ data: { id: "c".repeat(64), userId: f.userId, kind: "VERIFY", returnTo: "/", expiresAt: new Date(T0.getTime() + 60_000) } });

    const r = await change(f, STRONG, NEXT);
    expect(r).toEqual({ ok: true, data: { revokedSessions: 2 } });

    const sessions = await prisma.session.findMany({ where: { userId: f.userId }, select: { id: true } });
    expect(sessions.map((s) => s.id)).toEqual([f.current]);
    expect(await prisma.authChallenge.count({ where: { userId: f.userId } })).toBe(0);
    const u = await prisma.user.findUniqueOrThrow({ where: { id: f.userId } });
    expect(u).toMatchObject({ mustChangePassword: false, failedLogins: 0, passwordChangedAt: T0 });
    expect(await verifyPassword(NEXT, u.passwordHash ?? "")).toBe(true);
    expect(await verifyPassword(STRONG, u.passwordHash ?? "")).toBe(false);

    const [ev] = await auditOf("auth.password_changed");
    expect(ev).toMatchObject({ tenantId: TENANT_B, actor: "alice@bank-b.test", entity: "User", entityId: f.userId });
    expect(ev.payload).toMatchObject({ forced: false, selfService: true, revokedSessions: 2, ip: META.ip });
    expect(JSON.stringify(ev.payload)).not.toContain(NEXT);
  });

  it("writes platform users' events to the platform chain", async () => {
    const f = await seedUser(null, "ops@platform.test");
    expect((await change(f, STRONG, NEXT)).ok).toBe(true);
    const [ev] = await auditOf("auth.password_changed");
    expect(ev.tenantId).toBeNull();
  });

  it("rejects a session that is not the user's own", async () => {
    const a = await seedUser(TENANT_B);
    const b = await seedUser(TENANT_B, "bob@bank-b.test");
    const r = await changeOwnPassword({ userId: a.userId, sessionId: b.current }, { currentPassword: STRONG, newPassword: NEXT, confirmPassword: NEXT }, META, T0);
    expect(r).toMatchObject({ ok: false, status: 401 });
    expect(await prisma.session.count()).toBe(6);
  });
});

describe("sign out of all other sessions", () => {
  it("revokes every other session of the user only, keeps the current one, audited", async () => {
    const f = await seedUser(TENANT_B);
    const other = await seedUser(TENANT_B, "bob@bank-b.test");
    expect(await revokeOtherSessions(ctxOf(f), META)).toEqual({ ok: true, data: { revokedSessions: 2 } });
    expect((await prisma.session.findMany({ where: { userId: f.userId } })).map((s) => s.id)).toEqual([f.current]);
    expect(await prisma.session.count({ where: { userId: other.userId } })).toBe(3);
    const [ev] = await auditOf("auth.sessions_revoked");
    expect(ev).toMatchObject({ tenantId: TENANT_B, entityId: f.userId });
    expect(ev.payload).toMatchObject({ scope: "others", revokedSessions: 2 });
  });

  it("overview lists live sessions and marks the current one", async () => {
    const f = await seedUser(TENANT_B);
    const o = await getAccountOverview(f.userId, f.current, 15, T0);
    expect(o).toMatchObject({ upn: "alice@bank-b.test", role: "ADMIN", bankName: "Demo Bank B", hasPassword: true });
    expect(o?.sessions).toHaveLength(3);
    expect(o?.sessions.filter((s) => s.current)).toHaveLength(1);
    // Idle sessions are not shown.
    expect((await getAccountOverview(f.userId, f.current, 15, new Date(T0.getTime() + 16 * 60_000)))?.sessions).toHaveLength(0);
  });
});
