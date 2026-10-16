// Lab-only client for PatchGate's REAL HTTP API, signed in as a lab user with password (+ TOTP when the
// server runs AUTH_MFA=required; with AUTH_MFA=off — the lab default — the password step already signs in).
// Credentials live in lab/patchgate/lab-users.json (gitignored, written by users.sh); the TOTP secret is
// captured at the user's first sign-in (enrolment) and stored there too, so scripts and the Playwright
// lab tests can produce codes. Sessions are cached in lab/patchgate/.sessions.json (gitignored).
//
//   node lab/patchgate/pg-api.mjs <upn> GET  /api/admin/tenants
//   node lab/patchgate/pg-api.mjs <upn> POST /api/admin/tenants '{"slug":"bank-a","name":"Bank A"}'
//   node lab/patchgate/pg-api.mjs totp <upn>          # current 6-digit code (manual browser sign-in)
// Needs NODE_EXTRA_CA_CERTS=lab/certs/out/ca.crt (env.sh sets it). Prints the JSON body; exit 1 if !success.
import { createHmac } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const USERS = join(here, "lab-users.json");
const SESSIONS = join(here, ".sessions.json");
const BASE = process.env.PG_URL ?? "https://patchgate.patchgate-lab.internal:3443";

const readJson = (f, d) => (existsSync(f) ? JSON.parse(readFileSync(f, "utf8")) : d);
const writeJson = (f, v) => writeFileSync(f, JSON.stringify(v, null, 2), { mode: 0o600 });

export function base32Decode(s) {
  const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, value = 0;
  const out = [];
  for (const ch of s.replace(/[\s=-]/g, "").toUpperCase()) {
    value = ((value << 5) | A.indexOf(ch)) & 0xffff;
    bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  return Buffer.from(out);
}

export function totpAt(secret, step) {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(step));
  const mac = createHmac("sha1", base32Decode(secret)).update(msg).digest();
  const o = mac[mac.length - 1] & 0x0f;
  const bin = ((mac[o] & 0x7f) << 24) | (mac[o + 1] << 16) | (mac[o + 2] << 8) | mac[o + 3];
  return String(bin % 1_000_000).padStart(6, "0");
}

const stepNow = () => Math.floor(Date.now() / 30_000);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** A fresh, never-used TOTP step for this user (codes are single use per step, server-enforced). */
export async function freshCode(upn) {
  for (;;) {
    const users = readJson(USERS, { users: {} });
    const u = users.users[upn];
    if (!u?.totpSecret) throw new Error(`no TOTP secret recorded for ${upn}`);
    const s = stepNow();
    if (s > (u.lastStep ?? 0)) {
      u.lastStep = s;
      writeJson(USERS, users);
      return totpAt(u.totpSecret, s);
    }
    await sleep(((s + 1) * 30_000 - Date.now()) + 500);
  }
}

function cookieHeader(jar) {
  return Object.entries(jar).map(([k, v]) => `${k}=${v}`).join("; ");
}
function absorb(jar, res) {
  for (const c of res.headers.getSetCookie?.() ?? []) {
    const [pair, ...attrs] = c.split(";");
    const i = pair.indexOf("=");
    const name = pair.slice(0, i).trim();
    const value = pair.slice(i + 1).trim();
    const expired = attrs.some((a) => /max-age=0/i.test(a) || /expires=thu, 01 jan 1970/i.test(a));
    if (expired || value === "") delete jar[name];
    else jar[name] = value;
  }
}

async function raw(jar, method, path, body) {
  const res = await fetch(BASE + path, {
    method,
    redirect: "manual",
    headers: {
      origin: BASE,
      "content-type": "application/json",
      ...(Object.keys(jar).length ? { cookie: cookieHeader(jar) } : {}),
    },
    body: body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body),
  });
  absorb(jar, res);
  const text = await res.text();
  let json;
  try { json = JSON.parse(text); } catch { json = { success: false, error: text.slice(0, 300) }; }
  return { status: res.status, json };
}

function saveSession(upn, jar) {
  const s = readJson(SESSIONS, {});
  s[upn] = jar;
  writeJson(SESSIONS, s);
  return jar;
}

/** The server's second-factor mode from /api/health: "required" | "off" | "n/a" (null if unreachable). */
export async function serverMfa() {
  try {
    const r = await fetch(BASE + "/api/health");
    return (await r.json()).mfa ?? null;
  } catch {
    return null;
  }
}

/**
 * Sign in: password, then (AUTH_MFA=required) the TOTP code — enrolling the authenticator on first use.
 * With AUTH_MFA=off the password step returns "done" and no code is involved. Returns the cookie jar.
 */
export async function login(upn) {
  const users = readJson(USERS, { users: {} });
  const u = users.users[upn];
  if (!u) throw new Error(`unknown lab user ${upn} (see lab/patchgate/lab-users.json)`);
  for (let attempt = 0; attempt < 3; attempt++) {
    const jar = {};
    const p = await raw(jar, "POST", "/api/auth/password", { upn, password: u.password, returnTo: "/" });
    if (!p.json.success) throw new Error(`password step for ${upn}: ${p.status} ${p.json.error}`);
    if (p.json.data.step === "done") return saveSession(upn, jar); // AUTH_MFA=off: password only
    if (p.json.data.step === "change-password") throw new Error(`${upn} must change the password first`);
    if (p.json.data.step === "enroll") {
      const all = readJson(USERS, { users: {} });
      all.users[upn].totpSecret = p.json.data.secret.replace(/\s/g, "");
      writeJson(USERS, all);
    }
    const t = await raw(jar, "POST", "/api/auth/totp", { code: await freshCode(upn) });
    if (t.json.success && t.json.data.step === "done") return saveSession(upn, jar);
    if (t.json.success && t.json.data.step === "change-password") throw new Error(`${upn} must change the password first`);
    console.error(`totp step for ${upn}: ${t.status} ${t.json.error} — retrying`);
  }
  throw new Error(`could not sign in ${upn}`);
}

/** Call the API as `upn`, re-using a cached session and signing in again when it expired. */
export async function api(upn, method, path, body) {
  let jar = readJson(SESSIONS, {})[upn] ?? (await login(upn));
  let r = await raw(jar, method, path, body);
  if (r.status === 401) {
    jar = await login(upn);
    r = await raw(jar, method, path, body);
  }
  const s = readJson(SESSIONS, {});
  s[upn] = jar;
  writeJson(SESSIONS, s);
  return r;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const [a, b, c, d] = process.argv.slice(2);
  try {
    if (a === "totp") {
      console.log(await freshCode(b));
    } else if (a === "login") {
      await login(b);
      console.log(`signed in ${b}`);
    } else {
      const r = await api(a, b.toUpperCase(), c, d);
      console.log(JSON.stringify(r.json));
      process.exitCode = r.json.success === false || r.status >= 400 ? 1 : 0;
    }
  } catch (err) {
    console.error(String(err?.message ?? err));
    process.exitCode = 1;
  }
}
