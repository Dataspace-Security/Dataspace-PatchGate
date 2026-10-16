/**
 * AUTH_ENC_KEY rotation (RUNBOOK §9.4) against a real PostgreSQL: the re-encryption core used by
 * scripts/admin/rotate-auth-enc-key.ts, plus sign-in before/after rotation and after removing the old key.
 * Run: TEST_DATABASE_URL=postgresql://…/patchgate_test_auth npm run test:int -- src/test/auth-rotation.int.test.ts
 */
import { createCipheriv, randomBytes } from "node:crypto";
import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";
import { configureTestEnv, resetDb, TENANT_B } from "./helpers";

const OLD = "ab".repeat(32);
const NEW = "5e".repeat(32);
const STRANGER = "77".repeat(32);
configureTestEnv({ AUTH_MODE: "local", AUTH_ENC_KEY: NEW, AUTH_ENC_KEY_PREVIOUS: OLD });

const { prisma } = await import("@/lib/db");
const { rotateAuthEncKey, ROTATION_ACTOR } = await import("@/lib/auth/enc-key-rotation");
const { encryptSecret, keyId, openSecret } = await import("@/lib/auth/secret-box");
const { authKeyring } = await import("@/lib/auth/enc-keys");
const { beginPasswordLogin, verifyTotpStep } = await import("@/lib/auth/local-login");
const { hashPassword } = await import("@/lib/auth/password");
const { generateTotpSecret, hotp, totpStep } = await import("@/lib/auth/totp");

const META = { ip: "10.0.0.7", userAgent: "vitest" };
const T0 = new Date("2026-10-16T10:00:00Z");
const at = (minutes: number) => new Date(T0.getTime() + minutes * 60_000);
const STRONG = "orbit-Kettle-7-sandstone-river";
const RING = { current: NEW, previous: OLD };

/** Pre-key-id ciphertext ("v1.iv.tag.ct", AAD = owner), as written before rotation support existed. */
function legacyBox(plain: Buffer, keyHex: string, owner: string): string {
  const iv = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", Buffer.from(keyHex, "hex"), iv, { authTagLength: 16 });
  c.setAAD(Buffer.from(owner, "utf8"));
  const ct = Buffer.concat([c.update(plain), c.final()]);
  return ["v1", iv.toString("base64url"), c.getAuthTag().toString("base64url"), ct.toString("base64url")].join(".");
}

interface Enrolled {
  id: string;
  upn: string;
  secret: Buffer;
}

async function enrolled(upn: string, encrypt: (secret: Buffer, owner: string) => string): Promise<Enrolled> {
  const secret = generateTotpSecret();
  const u = await prisma.user.create({ data: { upn, name: upn, role: "VIEWER", tenantId: TENANT_B, passwordHash: await hashPassword(STRONG), totpEnabled: true } });
  await prisma.user.update({ where: { id: u.id }, data: { totpSecretEnc: encrypt(secret, u.id) } });
  return { id: u.id, upn, secret };
}

type LoginFns = { beginPasswordLogin: typeof beginPasswordLogin; verifyTotpStep: typeof verifyTotpStep };

async function signIn(fns: LoginFns, u: Enrolled, when: Date): Promise<boolean> {
  const p = await fns.beginPasswordLogin({ upn: u.upn, password: STRONG }, META, when);
  if (!p.ok || p.step !== "verify") throw new Error(`unexpected first step: ${JSON.stringify(p)}`);
  const r = await fns.verifyTotpStep(p.challengeToken, hotp(u.secret, totpStep(when.getTime())), META, when);
  return r.ok && r.step === "done";
}

async function seed() {
  const a = await enrolled("a@bank-b.test", (s, o) => encryptSecret(s, OLD, o)); // old key, key-id format
  const b = await enrolled("b@bank-b.test", (s, o) => legacyBox(s, OLD, o)); // old key, legacy format
  const c = await enrolled("c@bank-b.test", (s, o) => encryptSecret(s, NEW, o)); // already current
  const pendingOwner = await prisma.user.create({ data: { upn: "d@bank-b.test", name: "d", role: "VIEWER", tenantId: TENANT_B, passwordHash: await hashPassword(STRONG) } });
  const pendingSecret = generateTotpSecret();
  await prisma.authChallenge.create({
    data: { id: "e".repeat(64), userId: pendingOwner.id, kind: "ENROLL", returnTo: "/", pendingSecretEnc: encryptSecret(pendingSecret, OLD, pendingOwner.id), expiresAt: at(5) },
  });
  return { a, b, c, pendingOwner, pendingSecret };
}

beforeEach(async () => {
  await resetDb(prisma);
});
afterAll(() => prisma.$disconnect());

describe("AUTH_ENC_KEY rotation", () => {
  it("app reads the keyring from AUTH_ENC_KEY + AUTH_ENC_KEY_PREVIOUS", () => {
    expect(authKeyring()).toEqual({ current: NEW, previous: OLD });
  });

  it("dry run counts without writing or auditing", async () => {
    const { a } = await seed();
    const before = (await prisma.user.findUniqueOrThrow({ where: { id: a.id } })).totpSecretEnc;
    const r = await rotateAuthEncKey({ ring: RING, dryRun: true });
    expect(r.users).toEqual({ scanned: 3, reencrypted: 2, alreadyCurrent: 1, failed: 0, skippedConcurrent: 0 });
    expect(r.challenges).toMatchObject({ scanned: 1, reencrypted: 1 });
    expect((await prisma.user.findUniqueOrThrow({ where: { id: a.id } })).totpSecretEnc).toBe(before);
    expect(await prisma.auditEvent.count({ where: { action: "auth.enc_key_rotated" } })).toBe(0);
  });

  it("re-encrypts in batches, is idempotent, audits once with counts, and sign-in keeps working", async () => {
    const { a, b, c, pendingOwner, pendingSecret } = await seed();
    // During the rotation window (PREVIOUS configured) users enrolled under the old key still sign in.
    expect(await signIn({ beginPasswordLogin, verifyTotpStep }, a, at(0))).toBe(true);
    expect(await signIn({ beginPasswordLogin, verifyTotpStep }, b, at(0))).toBe(true);

    const r = await rotateAuthEncKey({ ring: RING, batchSize: 2 });
    expect(r).toMatchObject({ dryRun: false, currentKeyId: keyId(NEW), previousKeyId: keyId(OLD) });
    expect(r.users).toEqual({ scanned: 3, reencrypted: 2, alreadyCurrent: 1, failed: 0, skippedConcurrent: 0 });
    expect(r.challenges).toEqual({ scanned: 1, reencrypted: 1, alreadyCurrent: 0, failed: 0, skippedConcurrent: 0 });

    for (const u of [a, b, c]) {
      const box = (await prisma.user.findUniqueOrThrow({ where: { id: u.id } })).totpSecretEnc ?? "";
      expect(box.endsWith(`.${keyId(NEW)}`)).toBe(true);
      expect(openSecret(box, { current: NEW }, u.id).plain.equals(u.secret)).toBe(true); // no old key needed
    }
    const ch = await prisma.authChallenge.findUniqueOrThrow({ where: { id: "e".repeat(64) } });
    expect(openSecret(ch.pendingSecretEnc ?? "", { current: NEW }, pendingOwner.id).plain.equals(pendingSecret)).toBe(true);

    const again = await rotateAuthEncKey({ ring: RING });
    expect(again.users).toEqual({ scanned: 3, reencrypted: 0, alreadyCurrent: 3, failed: 0, skippedConcurrent: 0 });
    expect(again.challenges).toMatchObject({ reencrypted: 0, alreadyCurrent: 1 });

    const events = await prisma.auditEvent.findMany({ where: { action: "auth.enc_key_rotated" }, orderBy: { seq: "asc" } });
    expect(events).toHaveLength(2); // one per real run
    expect(events[0]).toMatchObject({ tenantId: null, actor: ROTATION_ACTOR, entity: "AuthEncKey", entityId: keyId(NEW) });
    expect(events[0].payload).toMatchObject({ previousKeyId: keyId(OLD), users: { reencrypted: 2, alreadyCurrent: 1 }, challenges: { reencrypted: 1 } });
    const raw = JSON.stringify(events.map((e) => e.payload));
    expect(raw).not.toContain(OLD);
    expect(raw).not.toContain(NEW);

    // Step 4 of the procedure: remove AUTH_ENC_KEY_PREVIOUS and restart — everything still decrypts.
    delete process.env.AUTH_ENC_KEY_PREVIOUS;
    vi.resetModules();
    const fresh = await import("@/lib/auth/local-login");
    const freshKeys = await import("@/lib/auth/enc-keys");
    const freshDb = await import("@/lib/db");
    try {
      expect(freshKeys.authKeyring()).toEqual({ current: NEW, previous: null });
      expect(await signIn(fresh, a, at(2))).toBe(true);
      expect(await signIn(fresh, b, at(2))).toBe(true);
      expect(await signIn(fresh, c, at(2))).toBe(true);
    } finally {
      process.env.AUTH_ENC_KEY_PREVIOUS = OLD;
      await freshDb.prisma.$disconnect();
    }
  });

  it("leaves undecryptable secrets untouched and reports them", async () => {
    const { a } = await seed();
    const alien = await enrolled("x@bank-b.test", (s, o) => encryptSecret(s, STRANGER, o));
    const alienBox = (await prisma.user.findUniqueOrThrow({ where: { id: alien.id } })).totpSecretEnc;
    const r = await rotateAuthEncKey({ ring: RING });
    expect(r.users).toEqual({ scanned: 4, reencrypted: 2, alreadyCurrent: 1, failed: 1, skippedConcurrent: 0 });
    expect((await prisma.user.findUniqueOrThrow({ where: { id: alien.id } })).totpSecretEnc).toBe(alienBox);
    expect(openSecret((await prisma.user.findUniqueOrThrow({ where: { id: a.id } })).totpSecretEnc ?? "", { current: NEW }, a.id).plain.equals(a.secret)).toBe(true);
  });

  it("without the previous key, old-key users cannot sign in (they need the rotation or an MFA reset)", async () => {
    const { a } = await seed();
    const box = (await prisma.user.findUniqueOrThrow({ where: { id: a.id } })).totpSecretEnc ?? "";
    expect(() => openSecret(box, { current: NEW }, a.id)).toThrow(/unknown key/);
  });
});
