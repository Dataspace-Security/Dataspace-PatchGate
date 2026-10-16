#!/usr/bin/env node
// Bundles the connector into a single ESM file: dist/patchgate-connector.mjs (zod inlined, node built-ins external).
import { build } from "esbuild";
import { readFileSync, chmodSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const pkg = JSON.parse(readFileSync(resolve(root, "package.json"), "utf8"));
const outfile = resolve(root, "dist", "patchgate-connector.mjs");

await build({
  entryPoints: [resolve(root, "src", "cli.ts")],
  outfile,
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node24",
  minify: false,
  sourcemap: false,
  legalComments: "inline",
  banner: { js: "#!/usr/bin/env node" },
  define: { __CONNECTOR_VERSION__: JSON.stringify(pkg.version) },
  logLevel: "info",
});
try {
  chmodSync(outfile, 0o755);
} catch {
  // not supported on every filesystem (e.g. Windows); harmless
}
