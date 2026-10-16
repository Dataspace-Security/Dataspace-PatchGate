// Lab only: print one lab account's sign-in details in YOUR terminal (never logged).
//   node lab/patchgate/show-login.mjs lab-admin@patchgate.lab
// Local sign-in is password-only: username + password, no code.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

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
