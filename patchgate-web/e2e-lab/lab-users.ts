import { createHmac } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

/**
 * Lab accounts (lab/patchgate/lab-users.json, gitignored, written by lab/patchgate/users.sh). The TOTP
 * secret is recorded at a user's first sign-in (enrolment) — by these tests or by lab/patchgate/pg-api.mjs —
 * and `lastStep` is shared with pg-api.mjs because the server accepts each 30-s step only once per user.
 */
const USERS_FILE = join(__dirname, "..", "..", "lab", "patchgate", "lab-users.json");

export interface LabUser {
  password: string;
  role: string;
  tenant: string | null;
  totpSecret?: string;
  lastStep?: number;
}

interface UsersFile {
  users: Record<string, LabUser>;
}

function readUsers(): UsersFile {
  if (!existsSync(USERS_FILE)) throw new Error(`missing ${USERS_FILE} — run lab/up-all.sh first`);
  return JSON.parse(readFileSync(USERS_FILE, "utf8")) as UsersFile;
}

export function labUser(upn: string): LabUser {
  const u = readUsers().users[upn];
  if (!u) throw new Error(`unknown lab user ${upn}`);
  return u;
}

export function recordTotpSecret(upn: string, secret: string): void {
  const f = readUsers();
  f.users[upn] = { ...f.users[upn], totpSecret: secret.replace(/\s/g, "") };
  writeFileSync(USERS_FILE, JSON.stringify(f, null, 2), { mode: 0o600 });
}

function base32Decode(s: string): Buffer {
  const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of s.replace(/[\s=-]/g, "").toUpperCase()) {
    value = ((value << 5) | A.indexOf(ch)) & 0xffff;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/** RFC 6238 TOTP (SHA-1, 6 digits, 30 s) — the same parameters the app enrols. */
export function totpAt(secret: string, step: number): string {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(step));
  const mac = createHmac("sha1", base32Decode(secret)).update(msg).digest();
  const o = mac[mac.length - 1] & 0x0f;
  const bin = ((mac[o] & 0x7f) << 24) | (mac[o + 1] << 16) | (mac[o + 2] << 8) | mac[o + 3];
  return String(bin % 1_000_000).padStart(6, "0");
}

/** A code for a 30-s step this user has not used yet (waits for the next step when needed). */
export async function freshTotp(upn: string): Promise<string> {
  for (;;) {
    const f = readUsers();
    const u = f.users[upn];
    if (!u?.totpSecret) throw new Error(`no TOTP secret recorded for ${upn}`);
    const step = Math.floor(Date.now() / 30_000);
    if (step > (u.lastStep ?? 0)) {
      f.users[upn] = { ...u, lastStep: step };
      writeFileSync(USERS_FILE, JSON.stringify(f, null, 2), { mode: 0o600 });
      return totpAt(u.totpSecret, step);
    }
    await new Promise((r) => setTimeout(r, (step + 1) * 30_000 - Date.now() + 500));
  }
}
