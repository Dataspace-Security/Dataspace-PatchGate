import { describe, expect, it } from "vitest";
import { checkPasswordPolicy, dummyPasswordHash, generateTempPassword, hashPassword, verifyPassword } from "./password";

describe("scrypt password hashing", () => {
  it("hashes in the documented format and verifies", async () => {
    const h = await hashPassword("correct horse battery staple");
    expect(h).toMatch(/^scrypt\$32768\$8\$1\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$/);
    const [, , , , salt, key] = h.split("$");
    expect(Buffer.from(salt, "base64").length).toBe(16);
    expect(Buffer.from(key, "base64").length).toBe(64);
    expect(await verifyPassword("correct horse battery staple", h)).toBe(true);
    expect(await verifyPassword("correct horse battery stapl", h)).toBe(false);
  });

  it("uses a fresh salt per hash", async () => {
    const [a, b] = await Promise.all([hashPassword("same password here!"), hashPassword("same password here!")]);
    expect(a).not.toBe(b);
  });

  it("treats malformed or out-of-bounds stored hashes as non-matching", async () => {
    const h = await hashPassword("another long password");
    const parts = h.split("$");
    expect(await verifyPassword("x", "")).toBe(false);
    expect(await verifyPassword("x", "bcrypt$foo")).toBe(false);
    expect(await verifyPassword("another long password", ["scrypt", String(2 ** 30), ...parts.slice(2)].join("$"))).toBe(false);
    expect(await verifyPassword("another long password", [...parts.slice(0, 5), Buffer.alloc(8).toString("base64")].join("$"))).toBe(false);
  });

  it("detects a tampered hash", async () => {
    const h = await hashPassword("yet another passphrase");
    const parts = h.split("$");
    const key = Buffer.from(parts[5], "base64");
    key[0] ^= 1;
    expect(await verifyPassword("yet another passphrase", [...parts.slice(0, 5), key.toString("base64")].join("$"))).toBe(false);
  });

  it("provides a stable dummy hash for unknown users", async () => {
    const d = await dummyPasswordHash();
    expect(d).toBe(await dummyPasswordHash());
    expect(await verifyPassword("anything at all here", d)).toBe(false);
  });
});

describe("password policy", () => {
  const upn = "alice.smith@bank.example";
  it.each([
    ["short", /at least 14/],
    ["a".repeat(257), /at most 256/],
    ["alice.smith@bank.example", /username/],
    ["xxalice.smithyy-2026", /username/],
    ["aaaaaaaaaaaaaaaaaa", /repetitive/],
    ["passwordpassword", /common/],
    ["Password2026!!!!", /common/],
    ["P@ssw0rd-2026-01!", /common/],
    ["12345678901234", /common|repetitive/],
    ["Welcome123456789", /common/],
  ])("rejects %j", (pw, reason) => {
    const r = checkPasswordPolicy(pw, upn);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(reason);
  });

  it.each(["correct horse battery staple", "Tr0ub4dor&3-river-lamp", "blue-Kettle-7-orbit-sand"])("accepts %j", (pw) => {
    expect(checkPasswordPolicy(pw, upn)).toEqual({ ok: true });
  });

  it("generated temporary passwords satisfy the policy", () => {
    for (let i = 0; i < 50; i++) {
      const pw = generateTempPassword();
      expect(pw).toMatch(/^[A-Za-z2-9]{5}(-[A-Za-z2-9]{5}){3}$/);
      expect(checkPasswordPolicy(pw, upn)).toEqual({ ok: true });
    }
  });
});
