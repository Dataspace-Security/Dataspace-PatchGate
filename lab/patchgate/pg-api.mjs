// Lab-only client for PatchGate's REAL HTTP API, signed in as a lab user with username + password (local
// sign-in is password-only). Credentials live in lab/patchgate/lab-users.json (gitignored, written by users.sh):
// { "users": { "<upn>": { "password", "role", "tenant" } } }. Sessions are cached in lab/patchgate/.sessions.json
// (gitignored).
//
//   node lab/patchgate/pg-api.mjs <upn> GET  /api/admin/tenants
//   node lab/patchgate/pg-api.mjs <upn> POST /api/admin/tenants '{"slug":"bank-a","name":"Bank A"}'
//   node lab/patchgate/pg-api.mjs login <upn>          # sign in and cache the session
// Needs NODE_EXTRA_CA_CERTS=lab/certs/out/ca.crt (env.sh sets it). Prints the JSON body; exit 1 if !success.
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const USERS = join(here, "lab-users.json");
const SESSIONS = join(here, ".sessions.json");
const BASE = process.env.PG_URL ?? "https://patchgate.patchgate-lab.internal:3443";

const readJson = (f, d) => (existsSync(f) ? JSON.parse(readFileSync(f, "utf8")) : d);
const writeJson = (f, v) => writeFileSync(f, JSON.stringify(v, null, 2), { mode: 0o600 });

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

/** Sign in with username + password (one step). Returns the cookie jar. */
export async function login(upn) {
  const users = readJson(USERS, { users: {} });
  const u = users.users[upn];
  if (!u) throw new Error(`unknown lab user ${upn} (see lab/patchgate/lab-users.json)`);
  for (let attempt = 0; attempt < 3; attempt++) {
    const jar = {};
    const p = await raw(jar, "POST", "/api/auth/password", { upn, password: u.password, returnTo: "/" });
    if (p.json.success && p.json.data.step === "done") return saveSession(upn, jar);
    if (p.json.success && p.json.data.step === "change-password") throw new Error(`${upn} must change the password first`);
    if (p.status !== 500) throw new Error(`sign-in for ${upn}: ${p.status} ${p.json.error}`);
    console.error(`sign-in for ${upn}: ${p.status} ${p.json.error} — retrying`);
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
    if (a === "login") {
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
