#!/usr/bin/env node
// Fails (exit 1) if src/protocol.ts is not byte-identical to the PatchGate server's copy.
// The server copy is the single source of truth: patchgate-web/src/lib/connector/protocol.ts.
// Override the location with PATCHGATE_PROTOCOL_SOURCE (e.g. in CI where the repos are checked out elsewhere).
import { readFileSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const local = resolve(here, "..", "src", "protocol.ts");
const upstream = process.env.PATCHGATE_PROTOCOL_SOURCE ?? resolve(here, "..", "..", "patchgate-web", "src", "lib", "connector", "protocol.ts");

if (!existsSync(upstream)) {
  console.error(`protocol sync: upstream file not found: ${upstream} (set PATCHGATE_PROTOCOL_SOURCE)`);
  process.exit(1);
}

const digest = (p) => createHash("sha256").update(readFileSync(p)).digest("hex");
const a = digest(local);
const b = digest(upstream);
if (a !== b) {
  console.error(`protocol sync: MISMATCH\n  connector ${local}\n    sha256 ${a}\n  server    ${upstream}\n    sha256 ${b}\nCopy the server file verbatim into src/protocol.ts.`);
  process.exit(1);
}
console.log(`protocol sync: OK (sha256 ${a.slice(0, 16)}…)`);
