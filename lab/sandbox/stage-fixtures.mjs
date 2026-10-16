// LAB: stage OUTDATED third-party installers (from the discovery cache) as the sandbox's pre-existing
// software. Writes generated/config/fixtures/* + fixtures.json (name, kind, switches, sha256, version).
// Chrome is skipped (its older == latest). Usage: node lab/sandbox/stage-fixtures.mjs
import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { basename, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const apps = join(here, "..", "apps");
const outDir = join(here, "generated", "config", "fixtures");
mkdirSync(outDir, { recursive: true });

const matrix = {
  ...JSON.parse(readFileSync(join(apps, "matrix.json"), "utf8")),
  ...(existsSync(join(apps, "matrix-extra.json")) ? JSON.parse(readFileSync(join(apps, "matrix-extra.json"), "utf8")) : {}),
};

const fixtures = [];
for (const [id, { older, latest }] of Object.entries(matrix)) {
  if (!older?.file || older.error || older.version === latest?.version) continue;
  const name = basename(older.file);
  copyFileSync(older.file, join(outDir, name));
  const sha256 = createHash("sha256").update(readFileSync(join(outDir, name))).digest("hex");
  fixtures.push({ id, name, version: older.version, kind: older.kind, installerType: older.installerType, switches: older.switches ?? "", sha256 });
  console.log(`staged ${id} ${older.version} (${older.kind}/${older.installerType})`);
}
writeFileSync(join(outDir, "..", "fixtures.json"), JSON.stringify(fixtures, null, 2));
console.log(`${fixtures.length} fixtures -> ${outDir}`);
