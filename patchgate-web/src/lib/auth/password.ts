import { randomBytes, randomInt, scrypt, timingSafeEqual, type ScryptOptions } from "node:crypto";

/**
 * Local account passwords: scrypt (memory-hard KDF from node:crypto) + password policy.
 * Stored format: scrypt$N$r$p$saltB64$hashB64 — parameters travel with the hash so they can be
 * raised later without invalidating existing accounts. Pure module (also used by the bootstrap CLI).
 */

export const SCRYPT_N = 2 ** 15;
export const SCRYPT_R = 8;
export const SCRYPT_P = 1;
const KEY_LEN = 64;
const SALT_LEN = 16;
// Bounds for parameters read back from the DB: a tampered row must not turn verify into a DoS.
const MIN_LOG_N = 14;
const MAX_LOG_N = 20;

export const PASSWORD_MIN = 14;
export const PASSWORD_MAX = 256;

function scryptAsync(password: string, salt: Buffer, keyLen: number, opts: ScryptOptions): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scrypt(password.normalize("NFKC"), salt, keyLen, opts, (err, key) => (err ? reject(err) : resolve(key)));
  });
}

const maxmemFor = (n: number, r: number) => 256 * n * r; // 2x the 128*N*r working set

export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(SALT_LEN);
  const key = await scryptAsync(password, salt, KEY_LEN, { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P, maxmem: maxmemFor(SCRYPT_N, SCRYPT_R) });
  return ["scrypt", SCRYPT_N, SCRYPT_R, SCRYPT_P, salt.toString("base64"), key.toString("base64")].join("$");
}

interface ParsedHash {
  n: number;
  r: number;
  p: number;
  salt: Buffer;
  key: Buffer;
}

function parseHash(stored: string): ParsedHash | null {
  const parts = stored.split("$");
  if (parts.length !== 6 || parts[0] !== "scrypt") return null;
  const [n, r, p] = parts.slice(1, 4).map((x) => Number.parseInt(x, 10));
  const logN = Math.log2(n);
  if (!Number.isInteger(logN) || logN < MIN_LOG_N || logN > MAX_LOG_N) return null;
  if (!Number.isInteger(r) || r < 1 || r > 32 || !Number.isInteger(p) || p < 1 || p > 16) return null;
  const salt = Buffer.from(parts[4], "base64");
  const key = Buffer.from(parts[5], "base64");
  if (salt.length < 16 || key.length < 32 || key.length > 128) return null;
  return { n, r, p, salt, key };
}

/** Constant-time verify. A malformed stored hash verifies as false (never throws). */
export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const h = parseHash(stored);
  if (!h) return false;
  const key = await scryptAsync(password, h.salt, h.key.length, { N: h.n, r: h.r, p: h.p, maxmem: maxmemFor(h.n, h.r) });
  return key.length === h.key.length && timingSafeEqual(key, h.key);
}

let dummy: Promise<string> | null = null;

/** A real hash of a random secret: verifying unknown users against it costs the same time as a real check. */
export function dummyPasswordHash(): Promise<string> {
  dummy ??= hashPassword(randomBytes(24).toString("base64"));
  return dummy;
}

// Small built-in deny list. Matched against the whole password and against its letters-only core,
// so "Password2026!!!!" is rejected as well as "passwordpassword".
const COMMON_WORDS = new Set([
  "password", "passw0rd", "passwort", "welcome", "letmein", "qwerty", "qwertyuiop", "asdfghjkl", "zxcvbnm",
  "admin", "administrator", "changeme", "default", "secret", "iloveyou", "monkey", "dragon", "master",
  "sunshine", "princess", "football", "baseball", "trustno", "superman", "batman", "login", "access",
  "patchgate", "dataspace", "bank", "banking", "summer", "winter", "spring", "autumn", "january",
  "abc", "abcdef", "abcdefgh", "test", "testing", "user", "root", "toor", "temp", "temporary",
]);
const COMMON_FULL = new Set([
  "passwordpassword", "password12345678", "password1234567", "1234567890123456", "12345678901234",
  "123456789012345", "qwertyuiopasdfgh", "qwertyuiopasdf", "1q2w3e4r5t6y7u8i", "1qaz2wsx3edc4rfv",
  "aaaaaaaaaaaaaa", "iloveyouiloveyou", "letmeinletmein", "welcomewelcome1", "abcdefghijklmn",
  "zaq12wsxcde34rfv", "qazwsxedcrfvtgb", "trustno1trustno1",
]);

export type PolicyResult = { ok: true } | { ok: false; reason: string };

/** Password policy for local accounts (bank requirement: ≥ 14 characters, no trivial choices). */
export function checkPasswordPolicy(password: string, upn: string): PolicyResult {
  if (password.length < PASSWORD_MIN) return { ok: false, reason: `Password must be at least ${PASSWORD_MIN} characters.` };
  if (password.length > PASSWORD_MAX) return { ok: false, reason: `Password must be at most ${PASSWORD_MAX} characters.` };
  const lower = password.toLowerCase();
  const login = upn.trim().toLowerCase();
  const localPart = login.split("@")[0] ?? "";
  if (lower === login || lower.includes(login) || (localPart.length >= 4 && lower.includes(localPart))) {
    return { ok: false, reason: "Password must not contain your username." };
  }
  if (new Set(lower).size < 5) return { ok: false, reason: "Password is too repetitive." };
  // Undo common substitutions ("P@ssw0rd") before comparing the letters-only core.
  const deleet = lower.replace(/[@4]/g, "a").replace(/0/g, "o").replace(/[1!|]/g, "i").replace(/3/g, "e").replace(/[5$]/g, "s").replace(/7/g, "t");
  const core = lower.replace(/[^a-z]/g, "");
  const coreDeleet = deleet.replace(/[^a-z]/g, "");
  // A common word padded with a few digits/symbols ("Welcome123456789") is still a common password.
  const paddedWord = [...COMMON_WORDS].some((w) => w.length >= 5 && deleet.includes(w) && deleet.length - w.length < 10);
  if (COMMON_FULL.has(lower) || COMMON_WORDS.has(core) || COMMON_WORDS.has(coreDeleet) || paddedWord || /^\d+$/.test(lower)) {
    return { ok: false, reason: "Password is too common. Choose a longer passphrase." };
  }
  return { ok: true };
}

// No look-alike characters (0/O, 1/l/I) — temporary passwords are read out or typed by hand.
const TEMP_ALPHABET = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";

/** One-time temporary password: 4 groups of 5 (≈ 115 bits), e.g. "Xk7pQ-mR3tz-…". */
export function generateTempPassword(): string {
  const groups: string[] = [];
  for (let g = 0; g < 4; g++) {
    let s = "";
    for (let i = 0; i < 5; i++) s += TEMP_ALPHABET[randomInt(TEMP_ALPHABET.length)];
    groups.push(s);
  }
  return groups.join("-");
}
