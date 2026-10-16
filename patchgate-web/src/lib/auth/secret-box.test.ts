import { describe, expect, it } from "vitest";
import { createCipheriv, randomBytes } from "node:crypto";
import { decryptSecret, encryptSecret, keyId, needsReencryption, openSecret } from "./secret-box";
import { failureOutcome, isLocked, LOCKOUT_MINUTES, MAX_FAILED_LOGINS } from "./lockout";

const KEY = "a1".repeat(32);
const OTHER = "b2".repeat(32);

describe("AES-256-GCM secret box", () => {
  const secret = Buffer.from("12345678901234567890");

  it("round-trips with a versioned format and random IV", () => {
    const a = encryptSecret(secret, KEY, "user-1");
    const b = encryptSecret(secret, KEY, "user-1");
    expect(a).toMatch(/^v1\.[\w-]+\.[\w-]+\.[\w-]+\.[0-9a-f]{8}$/);
    expect(a).not.toBe(b);
    expect(decryptSecret(a, KEY, "user-1").equals(secret)).toBe(true);
  });

  it("detects tampering of ciphertext, tag or IV", () => {
    const box = encryptSecret(secret, KEY, "user-1");
    const [v, iv, tag, ct, kid] = box.split(".");
    const flip = (s: string) => {
      const b = Buffer.from(s, "base64url");
      b[0] ^= 1;
      return b.toString("base64url");
    };
    expect(() => decryptSecret([v, iv, tag, flip(ct), kid].join("."), KEY, "user-1")).toThrow();
    expect(() => decryptSecret([v, iv, flip(tag), ct, kid].join("."), KEY, "user-1")).toThrow();
    expect(() => decryptSecret([v, flip(iv), tag, ct, kid].join("."), KEY, "user-1")).toThrow();
  });

  it("fails with the wrong key, the wrong owner, or an unknown version", () => {
    const box = encryptSecret(secret, KEY, "user-1");
    expect(() => decryptSecret(box, OTHER, "user-1")).toThrow();
    expect(() => decryptSecret(box, KEY, "user-2")).toThrow();
    expect(() => decryptSecret(box.replace(/^v1/, "v9"), KEY, "user-1")).toThrow(/Unsupported/);
    expect(() => decryptSecret("garbage", KEY, "user-1")).toThrow();
  });

  it("rejects a malformed key", () => {
    expect(() => encryptSecret(secret, "short", "u")).toThrow(/64 hex/);
  });
});

/** A ciphertext in the pre-key-id format ("v1.iv.tag.ct", AAD = owner), as stored before rotation support. */
function legacyBox(plain: Buffer, keyHex: string, owner: string): string {
  const iv = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", Buffer.from(keyHex, "hex"), iv, { authTagLength: 16 });
  c.setAAD(Buffer.from(owner, "utf8"));
  const ct = Buffer.concat([c.update(plain), c.final()]);
  return ["v1", iv.toString("base64url"), c.getAuthTag().toString("base64url"), ct.toString("base64url")].join(".");
}

describe("key ids and rotation keyring", () => {
  const secret = Buffer.from("12345678901234567890");
  const NEW = "c3".repeat(32);

  it("derives a stable 8-hex key id that differs per key and is embedded in the ciphertext", () => {
    expect(keyId(KEY)).toMatch(/^[0-9a-f]{8}$/);
    expect(keyId(KEY)).toBe(keyId(KEY.toUpperCase()));
    expect(keyId(KEY)).not.toBe(keyId(OTHER));
    expect(keyId(KEY)).not.toBe(KEY.slice(0, 8));
    expect(encryptSecret(secret, KEY, "u").split(".")[4]).toBe(keyId(KEY));
  });

  it("decrypts with the previous key and flags the box for re-encryption", () => {
    const old = encryptSecret(secret, OTHER, "user-1");
    const o = openSecret(old, { current: NEW, previous: OTHER }, "user-1");
    expect(o.plain.equals(secret)).toBe(true);
    expect(o).toMatchObject({ keyId: keyId(OTHER), usedPrevious: true, legacy: false });
    expect(needsReencryption(o)).toBe(true);
    const fresh = openSecret(encryptSecret(secret, NEW, "user-1"), { current: NEW, previous: OTHER }, "user-1");
    expect(fresh).toMatchObject({ keyId: keyId(NEW), usedPrevious: false, legacy: false });
    expect(needsReencryption(fresh)).toBe(false);
  });

  it("fails on an unknown key id, without the previous key, or for another owner", () => {
    const old = encryptSecret(secret, OTHER, "user-1");
    expect(() => openSecret(old, { current: NEW }, "user-1")).toThrow(/unknown key/);
    expect(() => openSecret(old, { current: NEW, previous: OTHER }, "user-2")).toThrow();
    expect(() => decryptSecret(old, NEW, "user-1")).toThrow(/different key/);
  });

  it("keeps legacy ciphertexts (no key id) readable with either key", () => {
    const legacyOld = legacyBox(secret, OTHER, "user-1");
    expect(decryptSecret(legacyOld, OTHER, "user-1").equals(secret)).toBe(true);
    const o = openSecret(legacyOld, { current: NEW, previous: OTHER }, "user-1");
    expect(o).toMatchObject({ usedPrevious: true, legacy: true });
    const legacyCur = openSecret(legacyBox(secret, NEW, "user-1"), { current: NEW, previous: OTHER }, "user-1");
    expect(legacyCur).toMatchObject({ usedPrevious: false, legacy: true });
    expect(needsReencryption(legacyCur)).toBe(true); // rewritten into the key-id format
    expect(() => openSecret(legacyOld, { current: NEW }, "user-1")).toThrow();
  });

  it("detects tampering, including swapping or stripping the key id", () => {
    const ring = { current: NEW, previous: OTHER };
    const box = encryptSecret(secret, NEW, "user-1");
    const parts = box.split(".");
    const b = Buffer.from(parts[3], "base64url");
    b[0] ^= 1;
    expect(() => openSecret([...parts.slice(0, 3), b.toString("base64url"), parts[4]].join("."), ring, "user-1")).toThrow();
    expect(() => openSecret([...parts.slice(0, 4), keyId(OTHER)].join("."), ring, "user-1")).toThrow(); // kid swapped
    expect(() => openSecret(parts.slice(0, 4).join("."), ring, "user-1")).toThrow(); // kid stripped (AAD differs)
    expect(() => openSecret([...parts.slice(0, 4), "XYZ"].join("."), ring, "user-1")).toThrow(/Malformed/);
  });
});

describe("lockout", () => {
  const now = new Date("2026-01-01T10:00:00Z");

  it("counts failures below the limit without locking", () => {
    for (let n = 1; n < MAX_FAILED_LOGINS; n++) {
      expect(failureOutcome(n, now)).toEqual({ failedLogins: n, lockedUntil: null, lockedNow: false });
    }
  });

  it("locks for 15 minutes on the 5th consecutive failure and resets the counter", () => {
    const o = failureOutcome(MAX_FAILED_LOGINS, now);
    expect(o.lockedNow).toBe(true);
    expect(o.failedLogins).toBe(0);
    expect(o.lockedUntil?.getTime()).toBe(now.getTime() + LOCKOUT_MINUTES * 60_000);
  });

  it("isLocked respects the expiry", () => {
    const until = new Date(now.getTime() + 60_000);
    expect(isLocked(null, now)).toBe(false);
    expect(isLocked(until, now)).toBe(true);
    expect(isLocked(until, new Date(until.getTime() + 1))).toBe(false);
  });
});
