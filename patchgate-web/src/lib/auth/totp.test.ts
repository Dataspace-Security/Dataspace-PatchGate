import { describe, expect, it } from "vitest";
import { base32Decode, base32Encode, generateTotpSecret, groupSecret, hotp, otpauthUri, totp, totpStep, verifyTotp } from "./totp";

describe("base32 (RFC 4648 §10 test vectors, unpadded)", () => {
  const vectors: [string, string][] = [
    ["", ""],
    ["f", "MY"],
    ["fo", "MZXQ"],
    ["foo", "MZXW6"],
    ["foob", "MZXW6YQ"],
    ["fooba", "MZXW6YTB"],
    ["foobar", "MZXW6YTBOI"],
  ];
  it.each(vectors)("encodes %j", (plain, enc) => {
    expect(base32Encode(Buffer.from(plain))).toBe(enc);
  });
  it.each(vectors)("decodes %j", (plain, enc) => {
    expect(base32Decode(enc).toString()).toBe(plain);
  });
  it("accepts padding, lower case, spaces and dashes", () => {
    expect(base32Decode("mzxw 6ytb-oi======").toString()).toBe("foobar");
  });
  it("rejects invalid characters", () => {
    expect(() => base32Decode("MZXW1")).toThrow(/base32/);
  });
  it("round-trips random secrets", () => {
    for (let i = 0; i < 20; i++) {
      const s = generateTotpSecret();
      expect(s.length).toBe(20);
      expect(base32Decode(base32Encode(s)).equals(s)).toBe(true);
    }
  });
});

describe("HOTP (RFC 4226 Appendix D)", () => {
  const key = Buffer.from("12345678901234567890");
  const expected = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"];
  it.each(expected.map((code, i) => [i, code] as const))("counter %i → %s", (counter, code) => {
    expect(hotp(key, counter)).toBe(code);
  });
});

describe("TOTP (RFC 6238 Appendix B, 8 digits)", () => {
  const sha1 = Buffer.from("12345678901234567890");
  const sha256 = Buffer.from("12345678901234567890123456789012");
  const sha512 = Buffer.from("1234567890".repeat(6) + "1234");
  const rows: [number, string, string, string][] = [
    [59, "94287082", "46119246", "90693936"],
    [1111111109, "07081804", "68084774", "25091201"],
    [1111111111, "14050471", "67062674", "99943326"],
    [1234567890, "89005924", "91819424", "93441116"],
    [2000000000, "69279037", "90698825", "38618901"],
    [20000000000, "65353130", "77737706", "47863826"],
  ];
  it.each(rows)("T=%i", (t, c1, c256, c512) => {
    expect(totp(sha1, t * 1000, 8, "sha1")).toBe(c1);
    expect(totp(sha256, t * 1000, 8, "sha256")).toBe(c256);
    expect(totp(sha512, t * 1000, 8, "sha512")).toBe(c512);
  });
});

describe("verifyTotp", () => {
  const key = Buffer.from("12345678901234567890");
  const now = 1_700_000_000_000;
  const step = totpStep(now);

  it("accepts the current code and returns its step", () => {
    expect(verifyTotp(key, hotp(key, step), now, null)).toBe(step);
  });
  it("accepts ±1 step of clock drift, but not ±2", () => {
    expect(verifyTotp(key, hotp(key, step - 1), now, null)).toBe(step - 1);
    expect(verifyTotp(key, hotp(key, step + 1), now, null)).toBe(step + 1);
    expect(verifyTotp(key, hotp(key, step - 2), now, null)).toBeNull();
    expect(verifyTotp(key, hotp(key, step + 2), now, null)).toBeNull();
  });
  it("rejects a step that was already used (replay) or an older one", () => {
    expect(verifyTotp(key, hotp(key, step), now, step)).toBeNull();
    expect(verifyTotp(key, hotp(key, step - 1), now, step - 1)).toBeNull();
    expect(verifyTotp(key, hotp(key, step + 1), now, step)).toBe(step + 1);
  });
  it("rejects malformed codes", () => {
    for (const bad of ["", "12345", "1234567", "12345a", " 123456"]) expect(verifyTotp(key, bad, now, null)).toBeNull();
  });
  it("rejects a code for another key", () => {
    expect(verifyTotp(Buffer.from("x".repeat(20)), hotp(key, step), now, null)).toBeNull();
  });
});

describe("otpauth URI", () => {
  it("contains issuer, account and parameters", () => {
    const uri = otpauthUri("PatchGate", "alice@bank.example", "JBSWY3DPEHPK3PXP");
    expect(uri).toBe(
      "otpauth://totp/PatchGate:alice%40bank.example?secret=JBSWY3DPEHPK3PXP&issuer=PatchGate&algorithm=SHA1&digits=6&period=30",
    );
  });
  it("groups the manual key", () => {
    expect(groupSecret("JBSWY3DPEHPK3PXP")).toBe("JBSW Y3DP EHPK 3PXP");
  });
});
