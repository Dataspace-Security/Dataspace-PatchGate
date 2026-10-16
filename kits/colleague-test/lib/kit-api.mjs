// PatchGate colleague test kit — client for PatchGate's REAL HTTP API (TEST KIT ONLY, not product code).
// Runs inside the kit's server container via the release's tools image (node 24):
//   docker run --rm --network host --user 0 -v /root/kit:/kit --entrypoint node patchgate-tools:<v> /kit/lib/kit-api.mjs <cmd>
//
//   setup                 first sign-in of the platform admin (temporary password from the installer -> new
//                         password + authenticator), bank "Test Bank" (test-bank), the test users (created
//                         through Administration -> Users API) and their first sign-in (TOTP enrolment).
//   enrol "<site name>"   one-time enrolment code + job-key fingerprint -> /kit/secret/enrol.env (0600)
//   totp <who>            current 6-digit code for <who> (a key from users.conf, e.g. approver)
//   check-login <who>     sign in with password + TOTP and call one API as that user (prints role/status)
//   logins                print logins.txt content (secrets!) — only redirected into a 0600 file by the kit
//
// Secrets live in /kit/secret/users.json (0600, root only, inside the container). Nothing secret is printed
// except by `totp` (a 30-second code) and `logins` (redirected into the kit's logins.txt by the caller).
import { createHmac, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync, chmodSync } from "node:fs";

const BASE = process.env.PG_URL ?? "https://patchgate.pgi.test";
const SECRET_DIR = "/kit/secret";
const USERS = `${SECRET_DIR}/users.json`;
// Who is who: /kit/users.conf, written by test-on-my-pc.sh from its KIT_BANK / KIT_USERS block (the ONE place
// where accounts and role names are defined). Lines: "BANK|slug|name" and "key|upn|name|role|platform|bank|what".
// The first platform ADMIN is created by the server installer; all others by `setup` through the admin API.
function readConfig() {
  const people = {};
  let bank = null;
  for (const raw of readFileSync("/kit/users.conf", "utf8").split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const f = line.split("|");
    if (f[0] === "BANK") bank = { slug: f[1], name: f[2] };
    else people[f[0]] = { upn: f[1], name: f[2], role: f[3], bank: f[4] === "bank", what: f[5] ?? "" };
  }
  if (!bank) throw new Error("users.conf has no BANK line");
  const first = Object.keys(people)[0];
  if (!first || people[first].bank || people[first].role !== "ADMIN") throw new Error("users.conf: the first account must be the platform ADMIN (created by the installer)");
  return { bank, people, installerAdmin: first };
}
const { bank: BANK, people: PEOPLE, installerAdmin: ADMIN_KEY } = readConfig();

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const log = (s) => process.stdout.write(`    ${s}\n`);

function readState() {
  return existsSync(USERS) ? JSON.parse(readFileSync(USERS, "utf8")) : { users: {} };
}
function writeState(s) {
  mkdirSync(SECRET_DIR, { recursive: true, mode: 0o700 });
  writeFileSync(USERS, JSON.stringify(s, null, 2), { mode: 0o600 });
  chmodSync(USERS, 0o600);
}
function newPassword() {
  // Random, >= 14 chars, no user name inside, not repetitive (password policy of the app).
  return `Kit-${randomBytes(6).toString("hex")}-${randomBytes(6).toString("hex")}-Pg`;
}

// ---------------------------------------------------------------- TOTP (RFC 6238, SHA-1, 30 s, 6 digits)
function base32Decode(s) {
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
function totpAt(secret, step) {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(step));
  const mac = createHmac("sha1", base32Decode(secret)).update(msg).digest();
  const o = mac[mac.length - 1] & 0x0f;
  const bin = ((mac[o] & 0x7f) << 24) | (mac[o + 1] << 16) | (mac[o + 2] << 8) | mac[o + 3];
  return String(bin % 1_000_000).padStart(6, "0");
}
const stepNow = () => Math.floor(Date.now() / 30_000);
/** A never-used TOTP step for this user (the server accepts each step only once). */
async function freshCode(key) {
  for (;;) {
    const st = readState();
    const u = st.users[key];
    if (!u?.totpSecret) throw new Error(`no authenticator secret recorded for ${key}`);
    const s = stepNow();
    if (s > (u.lastStep ?? 0)) {
      u.lastStep = s;
      writeState(st);
      return totpAt(u.totpSecret, s);
    }
    await sleep((s + 1) * 30_000 - Date.now() + 500);
  }
}

// ---------------------------------------------------------------- HTTP with a cookie jar
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
async function call(jar, method, path, body) {
  for (let attempt = 0; ; attempt++) {
    const res = await fetch(BASE + path, {
      method,
      redirect: "manual",
      headers: {
        origin: BASE,
        "content-type": "application/json",
        ...(Object.keys(jar).length ? { cookie: Object.entries(jar).map(([k, v]) => `${k}=${v}`).join("; ") } : {}),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    // nginx rate-limits /api/auth/* (10/min per address): wait and retry instead of failing.
    if ((res.status === 429 || res.status === 503) && attempt < 20) {
      await res.text();
      await sleep(7_000);
      continue;
    }
    absorb(jar, res);
    const text = await res.text();
    let json;
    try { json = JSON.parse(text); } catch { json = { success: false, error: `HTTP ${res.status}: ${text.slice(0, 200)}` }; }
    return { status: res.status, json };
  }
}

/** Full local sign-in: password -> (enrol authenticator) -> TOTP -> (forced password change) -> session. */
async function signIn(key) {
  const st = readState();
  const u = st.users[key];
  if (!u?.password) throw new Error(`no password recorded for ${key}`);
  for (let attempt = 0; attempt < 3; attempt++) {
    const jar = {};
    const p = await call(jar, "POST", "/api/auth/password", { upn: u.upn, password: u.password, returnTo: "/" });
    if (!p.json.success) throw new Error(`sign-in (password step) for ${u.upn}: ${p.status} ${p.json.error}`);
    if (p.json.data.step === "enroll") {
      const s2 = readState();
      s2.users[key].totpSecret = p.json.data.secret.replace(/\s/g, "");
      s2.users[key].otpauthUri = p.json.data.otpauthUri;
      writeState(s2);
      log(`${u.upn}: authenticator enrolled (secret recorded for logins.txt)`);
    }
    let t = await call(jar, "POST", "/api/auth/totp", { code: await freshCode(key) });
    if (t.json.success && t.json.data.step === "change-password") {
      const pw = newPassword();
      const c = await call(jar, "POST", "/api/auth/password/change", { newPassword: pw });
      if (!(c.json.success && c.json.data.step === "done")) throw new Error(`password change for ${u.upn}: ${c.status} ${c.json.error}`);
      const s3 = readState();
      s3.users[key].tempPassword = s3.users[key].password;
      s3.users[key].password = pw;
      s3.users[key].passwordChanged = true;
      writeState(s3);
      log(`${u.upn}: temporary password replaced at first sign-in (new one recorded for logins.txt)`);
      return jar;
    }
    if (t.json.success && t.json.data.step === "done") return jar;
    log(`${u.upn}: TOTP step answered ${t.status} ${t.json.error ?? ""} - retrying`);
  }
  throw new Error(`could not sign in ${u.upn}`);
}

function must(r, what) {
  if (!r.json.success) throw new Error(`${what}: HTTP ${r.status} ${r.json.error}`);
  return r.json.data;
}

// ---------------------------------------------------------------- commands
async function setup() {
  const st = readState();
  const adm = PEOPLE[ADMIN_KEY];
  if (!st.users[ADMIN_KEY]) {
    const tmp = `${SECRET_DIR}/admin-temp-password`;
    if (!existsSync(tmp)) throw new Error(`${tmp} missing (the installer's one-time password was not captured)`);
    const pw = readFileSync(tmp, "utf8").trim();
    if (!pw) throw new Error("captured installer password is empty");
    st.users[ADMIN_KEY] = { upn: adm.upn, role: adm.role, bank: null, password: pw, installerPassword: pw };
    writeState(st);
  }
  log(`signing in as the platform admin ${adm.upn} (real login API)`);
  const admin = await signIn(ADMIN_KEY);

  // Bank (Administration -> Banks). Creating it also creates the standard rollout rings.
  const tenants = must(await call(admin, "GET", "/api/admin/tenants"), "list banks");
  let bank = (tenants.items ?? tenants).find((t) => t.slug === BANK.slug);
  if (!bank) {
    bank = must(await call(admin, "POST", "/api/admin/tenants", { slug: BANK.slug, name: BANK.name, requireBankApproval: true }), "create bank");
    log(`bank "${BANK.name}" (${BANK.slug}) created: ${bank.id}`);
  } else log(`bank "${BANK.name}" exists: ${bank.id}`);
  const s0 = readState();
  s0.bankId = bank.id;
  writeState(s0);

  // Users (Administration -> Users): temporary password returned once.
  for (const [key, p] of Object.entries(PEOPLE)) {
    if (key === ADMIN_KEY) continue;
    const s = readState();
    if (!s.users[key]) {
      const r = await call(admin, "POST", "/api/admin/users", { upn: p.upn, name: p.name, role: p.role, tenantId: p.bank ? bank.id : null });
      const d = must(r, `create user ${p.upn}`);
      s.users[key] = { upn: p.upn, role: p.role, bank: p.bank ? BANK.slug : null, password: d.temporaryPassword };
      writeState(s);
      log(`user ${p.upn} (${p.role}${p.bank ? `, ${BANK.name}` : ", platform"}) created with a temporary password`);
    } else log(`user ${p.upn} exists`);
    if (!readState().users[key].passwordChanged) await signIn(key);
  }
  log("all test accounts can sign in (password + authenticator)");
}

async function enrol(siteName) {
  const st = readState();
  if (!st.bankId) throw new Error("run setup first");
  const admin = await signIn(ADMIN_KEY);
  const d = must(await call(admin, "POST", "/api/connector/admin/enrollments", { tenantId: st.bankId, name: siteName }), "create enrolment code");
  mkdirSync(SECRET_DIR, { recursive: true, mode: 0o700 });
  const f = `${SECRET_DIR}/enrol.env`;
  writeFileSync(f, `CODE='${d.code}'\nFP='${d.fingerprint}'\nSERVER='${d.serverUrl}'\n`, { mode: 0o600 });
  chmodSync(f, 0o600);
  log(`one-time enrolment code for site "${siteName}" created (valid until ${new Date(d.expiresAt).toISOString()}; not printed)`);
  log(`job-signing key fingerprint: ${d.fingerprint}`);
  log(`bundle version offered by the one-line install: ${d.bundleVersion ?? "none"}`);
}

async function checkLogin(key) {
  const st = readState();
  const u = st.users[key];
  if (!u) throw new Error(`unknown account ${key}`);
  const jar = await signIn(key);
  const r = await call(jar, "GET", "/api/change-requests");
  log(`${u.upn}: signed in with password + TOTP; GET /api/change-requests -> HTTP ${r.status} success=${r.json.success}`);
  if (r.status !== 200) process.exitCode = 1;
}

/** The core rule, through the real API: maker != checker and the bank must approve (platform staff cannot). */
async function crCheck(ringId, patchId, checkerKey) {
  const st = readState();
  if (!st.bankId) throw new Error("run setup first");
  if (!PEOPLE[checkerKey]) throw new Error(`unknown checker account ${checkerKey}`);
  const admin = await signIn(ADMIN_KEY);
  must(await call(admin, "POST", "/api/tenant/select", { tenantId: st.bankId }), "select Test Bank");
  const cr = must(
    await call(admin, "POST", "/api/change-requests", { title: "Kit check: maker/checker (TEST FIXTURE patch)", ticketRef: "KIT-1", ringId, patchIds: [patchId] }),
    "create change request",
  );
  log(`${PEOPLE[ADMIN_KEY].upn} (maker) created change request ${cr.id} for ${BANK.name}`);
  must(await call(admin, "POST", `/api/change-requests/${cr.id}/submit`, {}), "submit change request");
  log("submitted for approval");
  const self = await call(admin, "POST", `/api/change-requests/${cr.id}/approve`, { reason: "kit check: maker tries to approve" });
  if (self.json.success) throw new Error("UNEXPECTED: the maker (platform admin) could approve its own change request");
  log(`maker approves own request -> refused (HTTP ${self.status}: ${self.json.error})`);
  const checker = await signIn(checkerKey);
  const ok2 = await call(checker, "POST", `/api/change-requests/${cr.id}/approve`, { reason: "kit check: bank approval" });
  const d = must(ok2, `approve as ${PEOPLE[checkerKey].upn}`);
  log(`${PEOPLE[checkerKey].upn} (bank checker) approves -> HTTP ${ok2.status}, status ${d.status ?? d.changeRequest?.status ?? "?"}`);

  // Second request raised by a bank user: the platform admin is NOT the maker, but still cannot give the bank's yes.
  const bankMaker = Object.keys(PEOPLE).find((k) => PEOPLE[k].bank && k !== checkerKey && ["ADMIN", "OPERATOR", "APPROVER"].includes(PEOPLE[k].role));
  if (!bankMaker) return;
  const bm = await signIn(bankMaker);
  const cr2 = must(
    await call(bm, "POST", "/api/change-requests", { title: "Kit check: bank approval required (TEST FIXTURE patch)", ticketRef: "KIT-2", ringId, patchIds: [patchId] }),
    `create change request as ${PEOPLE[bankMaker].upn}`,
  );
  must(await call(bm, "POST", `/api/change-requests/${cr2.id}/submit`, {}), "submit second change request");
  log(`${PEOPLE[bankMaker].upn} (bank maker) created + submitted change request ${cr2.id}`);
  const plat = await call(admin, "POST", `/api/change-requests/${cr2.id}/approve`, { reason: "kit check: platform staff tries to approve" });
  const after = plat.json.success ? (plat.json.data.status ?? plat.json.data.changeRequest?.status) : null;
  if (plat.json.success && after === "APPROVED") throw new Error("UNEXPECTED: platform staff alone approved a bank change request");
  log(plat.json.success
    ? `platform admin approves -> recorded, but the request stays ${after} (the bank's approval is still required)`
    : `platform admin approves -> refused (HTTP ${plat.status}: ${plat.json.error})`);
  const fin = must(await call(checker, "POST", `/api/change-requests/${cr2.id}/approve`, { reason: "kit check: bank approval" }), "bank approval of the second request");
  log(`${PEOPLE[checkerKey].upn} approves -> status ${fin.status ?? fin.changeRequest?.status ?? "?"}`);
}

function logins() {
  const st = readState();
  const lines = [];
  for (const [key, p] of Object.entries(PEOPLE)) {
    const u = st.users[key];
    if (!u) continue;
    lines.push(`[${key}]  ${p.what}`);
    lines.push(`  sign-in name : ${u.upn}`);
    lines.push(`  password     : ${u.password}`);
    if (key === ADMIN_KEY && u.installerPassword) lines.push(`  (installer's one-time password was: ${u.installerPassword} - already used and replaced by the kit at first sign-in)`);
    else if (u.tempPassword) lines.push(`  (temporary password from Administration -> Users was: ${u.tempPassword} - already replaced at first sign-in)`);
    if (u.totpSecret) {
      lines.push(`  TOTP secret  : ${u.totpSecret}`);
      lines.push(`  otpauth URI  : ${u.otpauthUri ?? ""}`);
    }
    lines.push("");
  }
  process.stdout.write(lines.join("\n"));
}

const [cmd, arg] = process.argv.slice(2);
try {
  if (cmd === "setup") await setup();
  else if (cmd === "enrol") await enrol(arg || "Head office");
  else if (cmd === "totp") {
    if (!PEOPLE[arg]) throw new Error(`who? one of: ${Object.keys(PEOPLE).join(", ")}`);
    process.stdout.write(`${await freshCode(arg)}\n`);
  } else if (cmd === "check-login") await checkLogin(arg);
  else if (cmd === "cr-check") await crCheck(arg, process.argv[4], process.argv[5]);
  else if (cmd === "get") {
    // debugging aid: GET <path> as <who>, prints the JSON body
    const jar = await signIn(arg);
    const r = await call(jar, "GET", process.argv[4]);
    process.stdout.write(`${JSON.stringify(r.json).slice(0, 4000)}\n`);
  }
  else if (cmd === "logins") logins();
  else throw new Error("usage: kit-api.mjs setup | enrol <site> | totp <who> | check-login <who> | logins");
} catch (err) {
  process.stderr.write(`kit-api: ${err?.message ?? err}\n`);
  process.exitCode = 1;
}
