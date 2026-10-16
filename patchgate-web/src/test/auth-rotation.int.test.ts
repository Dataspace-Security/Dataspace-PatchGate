/**
 * AUTH_ENC_KEY rotation (RUNBOOK §9.4) against a real PostgreSQL: the re-encryption core used by
 * scripts/admin/rotate-auth-enc-key.ts. Since local sign-in is password-only, the key protects the notification
 * webhook URLs only (NotificationSetting boxes + WEBHOOK outbox targets); sign-in never needs it.
 * Run: TEST_DATABASE_URL=postgresql://…/patchgate_test_auth npm run test:int -- src/test/auth-rotation.int.test.ts
 */
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { configureTestEnv, resetDb, TENANT_A, TENANT_B } from "./helpers";

const OLD = "ab".repeat(32);
const NEW = "5e".repeat(32);
const STRANGER = "77".repeat(32);
configureTestEnv({ AUTH_MODE: "local", AUTH_ENC_KEY: NEW, AUTH_ENC_KEY_PREVIOUS: OLD });

const { prisma } = await import("@/lib/db");
const { rotateAuthEncKey, ROTATION_ACTOR } = await import("@/lib/auth/enc-key-rotation");
const { keyId } = await import("@/lib/auth/secret-box");
const { authKeyring } = await import("@/lib/auth/enc-keys");
const { openSettingUrl, sealSettingUrl } = await import("@/lib/notify/webhook-store");
const { beginPasswordLogin } = await import("@/lib/auth/local-login");
const { hashPassword } = await import("@/lib/auth/password");

const META = { ip: "10.0.0.7", userAgent: "vitest" };
const STRONG = "orbit-Kettle-7-sandstone-river";
const RING = { current: NEW, previous: OLD };
const URL_A = "https://hooks.rotation.example/services/tokenAAAA";
const URL_B = "https://hooks.rotation.example/services/tokenBBBB";
const URL_P = "https://hooks.rotation.example/services/tokenPPPP";

async function seed() {
  await prisma.notificationSetting.createMany({
    data: [
      { scope: TENANT_A, tenantId: TENANT_A, webhookUrlsEnc: [sealSettingUrl(URL_A, TENANT_A, { current: OLD })] }, // old key
      { scope: TENANT_B, tenantId: TENANT_B, webhookUrlsLegacy: [URL_B] }, // plaintext from before encryption
      { scope: "platform", tenantId: null, webhookUrlsEnc: [sealSettingUrl(URL_P, "platform", { current: NEW })] }, // already current
    ],
  });
}

const boxesOf = async (scope: string) => (await prisma.notificationSetting.findUniqueOrThrow({ where: { scope } })).webhookUrlsEnc;

beforeEach(async () => {
  await resetDb(prisma);
  await prisma.notificationSetting.deleteMany();
});
afterAll(() => prisma.$disconnect());

describe("AUTH_ENC_KEY rotation", () => {
  it("app reads the keyring from AUTH_ENC_KEY + AUTH_ENC_KEY_PREVIOUS", () => {
    expect(authKeyring()).toEqual({ current: NEW, previous: OLD });
  });

  it("the report covers webhook URLs only (no TOTP secrets are stored any more)", async () => {
    const r = await rotateAuthEncKey({ ring: RING, dryRun: true });
    expect(Object.keys(r).sort()).toEqual(["currentKeyId", "dryRun", "previousKeyId", "webhookOutbox", "webhookSettings"]);
  });

  it("dry run counts without writing or auditing", async () => {
    await seed();
    const before = await boxesOf(TENANT_A);
    const r = await rotateAuthEncKey({ ring: RING, dryRun: true });
    expect(r.webhookSettings).toEqual({ scanned: 3, reencrypted: 2, alreadyCurrent: 1, failed: 0, skippedConcurrent: 0 });
    expect(await boxesOf(TENANT_A)).toEqual(before);
    expect(await prisma.auditEvent.count({ where: { action: "auth.enc_key_rotated" } })).toBe(0);
  });

  it("re-encrypts in batches, is idempotent and audits once per run with counts (never a key or URL)", async () => {
    await seed();
    const r = await rotateAuthEncKey({ ring: RING, batchSize: 2 });
    expect(r).toMatchObject({ dryRun: false, currentKeyId: keyId(NEW), previousKeyId: keyId(OLD) });
    expect(r.webhookSettings).toEqual({ scanned: 3, reencrypted: 2, alreadyCurrent: 1, failed: 0, skippedConcurrent: 0 });

    for (const [scope, url] of [[TENANT_A, URL_A], [TENANT_B, URL_B], ["platform", URL_P]] as const) {
      const [box] = await boxesOf(scope);
      expect(box.endsWith(`.${keyId(NEW)}`)).toBe(true);
      expect(openSettingUrl(box, scope, { current: NEW }).url).toBe(url); // no old key needed
    }
    expect((await prisma.notificationSetting.findUniqueOrThrow({ where: { scope: TENANT_B } })).webhookUrlsLegacy).toEqual([]);

    const again = await rotateAuthEncKey({ ring: RING });
    expect(again.webhookSettings).toEqual({ scanned: 3, reencrypted: 0, alreadyCurrent: 3, failed: 0, skippedConcurrent: 0 });

    const events = await prisma.auditEvent.findMany({ where: { action: "auth.enc_key_rotated" }, orderBy: { seq: "asc" } });
    expect(events).toHaveLength(2);
    expect(events[0]).toMatchObject({ tenantId: null, actor: ROTATION_ACTOR, entity: "AuthEncKey", entityId: keyId(NEW) });
    expect(events[0].payload).toMatchObject({ previousKeyId: keyId(OLD), webhookSettings: { reencrypted: 2, alreadyCurrent: 1 } });
    expect(events[0].payload).not.toHaveProperty("users");
    const raw = JSON.stringify(events.map((e) => e.payload));
    for (const secret of [OLD, NEW, "tokenAAAA", "tokenBBBB"]) expect(raw).not.toContain(secret);
  });

  it("leaves undecryptable boxes untouched and reports them", async () => {
    const alien = sealSettingUrl(URL_A, TENANT_A, { current: STRANGER });
    await prisma.notificationSetting.create({ data: { scope: TENANT_A, tenantId: TENANT_A, webhookUrlsEnc: [alien] } });
    const r = await rotateAuthEncKey({ ring: RING });
    expect(r.webhookSettings).toMatchObject({ scanned: 1, reencrypted: 0, failed: 1 });
    expect(await boxesOf(TENANT_A)).toEqual([alien]);
  });

  it("local sign-in does not depend on the key (password only)", async () => {
    await prisma.user.create({ data: { upn: "a@bank-b.test", name: "a", role: "AUDITOR", tenantId: TENANT_B, passwordHash: await hashPassword(STRONG) } });
    expect(await beginPasswordLogin({ upn: "a@bank-b.test", password: STRONG }, META)).toMatchObject({ ok: true, step: "done" });
  });
});
