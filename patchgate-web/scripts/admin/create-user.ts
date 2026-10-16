/**
 * Bootstrap / break-glass CLI: create a local PatchGate user (typically the FIRST platform admin).
 *
 *   npx tsx --env-file=.env scripts/admin/create-user.ts --upn admin@patchgate.example --name "Jane Admin" --role ADMIN
 *   npx tsx --env-file=.env scripts/admin/create-user.ts --upn ops@bank-a.example --name "Bank A Admin" --role ADMIN --tenant bank-a
 *   … add --generate to print a one-time temporary password instead of being prompted for one.
 *
 * The password is read without echo (or from stdin when piped), checked against the password policy,
 * stored only as a scrypt hash, and the creation is written to the audit log. Local sign-in is
 * password-only (banks needing MFA use their SSO).
 */
import { registerHooks } from "node:module";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { pathToFileURL } from "node:url";

// The app's server modules import "server-only" (which throws outside React Server Components).
// A CLI is server-side by definition: resolve it to the package's own empty module.
const require = createRequire(__filename);
const EMPTY = pathToFileURL(join(dirname(require.resolve("server-only")), "empty.js")).href;
registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === "server-only") return { url: EMPTY, shortCircuit: true };
    return nextResolve(specifier, context);
  },
});

import("./create-user-main")
  .then((m) => m.main(process.argv.slice(2)))
  .then((code) => {
    process.exitCode = code;
  })
  .catch((err: unknown) => {
    process.stderr.write(`create-user failed: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exitCode = 1;
  });
