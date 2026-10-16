import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

/**
 * TOTP second factor, implemented from the RFCs (no third-party OTP code in the login path):
 * RFC 4648 base32, RFC 4226 HOTP, RFC 6238 TOTP (SHA-1, 6 digits, 30-s steps, ±1 step drift).
 * Each accepted step is remembered per user (User.totpLastStep) so a code works only once.
 */

export const TOTP_PERIOD_SECONDS = 30;
export const TOTP_DIGITS = 6;
export const TOTP_WINDOW = 1;
const SECRET_BYTES = 20; // 160 bits, as recommended by RFC 4226 §4

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32Encode(buf: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

/** Case-insensitive; spaces, dashes and "=" padding are ignored. Throws on any other character. */
export function base32Decode(input: string): Buffer {
  const clean = input.replace(/[\s=-]/g, "").toUpperCase();
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = B32.indexOf(ch);
    if (idx < 0) throw new Error("Invalid base32 character");
    value = ((value << 5) | idx) & 0xffff;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

export type HmacAlgo = "sha1" | "sha256" | "sha512";

/** RFC 4226 HOTP with dynamic truncation. */
export function hotp(key: Uint8Array, counter: number | bigint, digits = TOTP_DIGITS, algo: HmacAlgo = "sha1"): string {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const mac = createHmac(algo, key).update(msg).digest();
  const offset = mac[mac.length - 1] & 0x0f;
  const bin = ((mac[offset] & 0x7f) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
  return String(bin % 10 ** digits).padStart(digits, "0");
}

export function totpStep(nowMs: number, period = TOTP_PERIOD_SECONDS): number {
  return Math.floor(nowMs / 1000 / period);
}

/** RFC 6238 TOTP for a given time. */
export function totp(key: Uint8Array, nowMs: number, digits = TOTP_DIGITS, algo: HmacAlgo = "sha1"): string {
  return hotp(key, totpStep(nowMs), digits, algo);
}

function sameCode(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

/**
 * Verify a 6-digit code within ±1 step. Returns the matched step, or null.
 * Steps at or before `lastStep` are refused (replay of an already-used code).
 */
export function verifyTotp(key: Uint8Array, code: string, nowMs: number, lastStep: number | null): number | null {
  if (!/^\d{6}$/.test(code)) return null;
  const now = totpStep(nowMs);
  let matched: number | null = null;
  // Check every candidate (no early exit) to keep timing independent of which step matched.
  for (let s = now - TOTP_WINDOW; s <= now + TOTP_WINDOW; s++) {
    if (sameCode(hotp(key, s), code) && (lastStep === null || s > lastStep) && matched === null) matched = s;
  }
  return matched;
}

export function generateTotpSecret(): Buffer {
  return randomBytes(SECRET_BYTES);
}

/** Key URI for authenticator apps (Google Authenticator / Microsoft Authenticator / FreeOTP). */
export function otpauthUri(issuer: string, account: string, secretB32: string): string {
  const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(account)}`;
  const q = new URLSearchParams({ secret: secretB32, issuer, algorithm: "SHA1", digits: String(TOTP_DIGITS), period: String(TOTP_PERIOD_SECONDS) });
  return `otpauth://totp/${label}?${q.toString()}`;
}

/** "JBSWY3DPEHPK3PXP…" → "JBSW Y3DP EHPK …" for manual entry. */
export function groupSecret(b32: string): string {
  return b32.replace(/(.{4})/g, "$1 ").trim();
}
