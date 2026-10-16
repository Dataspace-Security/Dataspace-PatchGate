// Lab only: print one lab account's sign-in details in YOUR terminal (never logged).
//   node lab/patchgate/show-login.mjs lab-admin@patchgate.lab
// The 6-digit code (only when the server runs AUTH_MFA=required) is valid for the current 30-second window.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { freshCode, serverMfa } from "./pg-api.mjs";

const upn = process.argv[2];
const users = JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), "lab-users.json"), "utf8")).users;
if (!upn || !users[upn]) {
  console.error(`usage: node lab/patchgate/show-login.mjs <account>\naccounts: ${Object.keys(users).join(", ")}`);
  process.exit(1);
}
const u = users[upn];
console.log(`URL      : https://patchgate.patchgate-lab.internal:3443`);
console.log(`Account  : ${upn}  (${u.role}, ${u.tenant ?? "platform"})`);
console.log(`Password : ${u.password}`);
// AUTH_MFA=off (lab default): no code at all. Asked from the running server (/api/health), else the env.
const mfa = (await serverMfa()) ?? process.env.AUTH_MFA ?? "required";
const code = mfa === "off" ? "not needed (AUTH_MFA=off)" : u.totpSecret ? await freshCode(upn) : "(set up at first sign-in: scan the QR code shown)";
console.log(`Code     : ${code}`);
