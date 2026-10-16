/**
 * AUTH_ENC_KEY rotation: re-encrypt every stored TOTP secret and notification webhook URL from the previous key
 * to the current one (also seals webhook URLs still stored in plaintext from before migration 20261016120000).
 *
 *   AUTH_ENC_KEY=<new> AUTH_ENC_KEY_PREVIOUS=<old> npx tsx --env-file=.env scripts/admin/rotate-auth-enc-key.ts --dry-run
 *   AUTH_ENC_KEY=<new> AUTH_ENC_KEY_PREVIOUS=<old> npx tsx --env-file=.env scripts/admin/rotate-auth-enc-key.ts
 *
 * Batched, one transaction per batch, idempotent (re-running changes nothing), prints counts only (never
 * secrets) and writes ONE platform audit event `auth.enc_key_rotated` (not on --dry-run). Exit code 1 when
 * some secret could not be decrypted with either key (those users need an MFA reset). Procedure: RUNBOOK §9.4.
 */
import { registerHooks, createRequire } from "node:module";
import { dirname, join } from "node:path";
import { parseArgs } from "node:util";
import { pathToFileURL } from "node:url";

// The app's server modules import "server-only" (which throws outside React Server Components).
const require = createRequire(__filename);
const EMPTY = pathToFileURL(join(dirname(require.resolve("server-only")), "empty.js")).href;
registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === "server-only") return { url: EMPTY, shortCircuit: true };
    return nextResolve(specifier, context);
  },
});

const USAGE = `Usage: npx tsx --env-file=.env scripts/admin/rotate-auth-enc-key.ts [--dry-run] [--batch-size N]
  Needs AUTH_ENC_KEY (new key) and normally AUTH_ENC_KEY_PREVIOUS (old key) in the environment.
  --dry-run       count what would change; no writes, no audit event
  --batch-size N  rows per transaction (1-1000, default 100)
`;

const out = (s: string) => process.stdout.write(`${s}\n`);

async function main(argv: string[]): Promise<number> {
  let values: { "dry-run"?: boolean; "batch-size"?: string; help?: boolean };
  try {
    ({ values } = parseArgs({
      args: argv,
      options: { "dry-run": { type: "boolean" }, "batch-size": { type: "string" }, help: { type: "boolean", short: "h" } },
      strict: true,
    }));
  } catch (e: unknown) {
    process.stderr.write(`Invalid arguments: ${e instanceof Error ? e.message : String(e)}\n\n${USAGE}`);
    return 2;
  }
  if (values.help) {
    out(USAGE);
    return 0;
  }
  const batchSize = values["batch-size"] === undefined ? undefined : Number(values["batch-size"]);
  if (batchSize !== undefined && (!Number.isInteger(batchSize) || batchSize < 1 || batchSize > 1000)) {
    process.stderr.write(`--batch-size must be an integer between 1 and 1000\n\n${USAGE}`);
    return 2;
  }

  const { authKeyring } = await import("../../src/lib/auth/enc-keys");
  const { rotateAuthEncKey } = await import("../../src/lib/auth/enc-key-rotation");
  const { prisma } = await import("../../src/lib/db");
  try {
    const ring = authKeyring(); // validates the whole configuration (env.ts), incl. PREVIOUS ≠ current
    if (!ring.previous) out("Note: AUTH_ENC_KEY_PREVIOUS is not set — only legacy-format secrets under the current key are rewritten.");
    const dryRun = values["dry-run"] ?? false;
    const r = await rotateAuthEncKey({ ring, dryRun, batchSize });
    out(`${dryRun ? "[dry run] " : ""}current key id ${r.currentKeyId}, previous key id ${r.previousKeyId ?? "(none)"}`);
    const rows = [
      ["users (TOTP secrets)", r.users],
      ["pending enrolments", r.challenges],
      ["notification settings (webhook URLs)", r.webhookSettings],
      ["notification outbox (webhook targets)", r.webhookOutbox],
    ] as const;
    for (const [label, c] of rows) {
      out(
        `  ${label}: scanned ${c.scanned}, ${dryRun ? "would re-encrypt" : "re-encrypted"} ${c.reencrypted}, already current ${c.alreadyCurrent}, ` +
          `undecryptable ${c.failed}, changed concurrently ${c.skippedConcurrent}`,
      );
    }
    const failed = r.users.failed + r.challenges.failed;
    if (failed > 0) out(`WARNING: ${failed} secret(s) could not be decrypted with either key — reset MFA for those users.`);
    const hookFailed = r.webhookSettings.failed + r.webhookOutbox.failed;
    if (hookFailed > 0) out(`WARNING: ${hookFailed} webhook row(s) could not be decrypted with either key — remove and re-add those webhooks.`);
    if (!dryRun) out("Audit event auth.enc_key_rotated written to the platform chain.");
    return failed + hookFailed > 0 ? 1 : 0;
  } finally {
    await prisma.$disconnect();
  }
}

main(process.argv.slice(2))
  .then((code) => {
    process.exitCode = code;
  })
  .catch((err: unknown) => {
    process.stderr.write(`rotate-auth-enc-key failed: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exitCode = 1;
  });
