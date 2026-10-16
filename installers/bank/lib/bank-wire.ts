/**
 * All-in-one bank server (installers/bank/install.sh): local wiring CLI, run in the tools image like
 * scripts/admin/create-user.ts (mounted next to it as scripts/admin/bank-wire.ts):
 *
 *   tenant <slug> "<name>"          create the bank (idempotent) -> BANKWIRE_TENANT=<id>
 *   enrol <tenantId> "<site name>"  one-time enrolment code for the local connector (env FP = the job-signing
 *                                   key fingerprint read from the signer's FINGERPRINTS.txt on this host)
 *                                   -> BANKWIRE_ENROL={"code":"…","fingerprint":"…"}  (the caller keeps it 0600)
 *
 * Same rules as the web UI: the bank gets the standard rings, everything is written to the audit chain
 * (actor "cli:bank-install"); only the SHA-256 of the code is stored.
 */
import { registerHooks, createRequire } from "node:module";
import { dirname, join } from "node:path";
import { pathToFileURL } from "node:url";

const require = createRequire(__filename);
const EMPTY = pathToFileURL(join(dirname(require.resolve("server-only")), "empty.js")).href;
registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === "server-only") return { url: EMPTY, shortCircuit: true };
    return nextResolve(specifier, context);
  },
});

import("./bank-wire-main")
  .then((m) => m.main(process.argv.slice(2)))
  .then((code) => {
    process.exitCode = code;
  })
  .catch((err: unknown) => {
    process.stderr.write(`bank-wire failed: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exitCode = 1;
  });
