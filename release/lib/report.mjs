#!/usr/bin/env node
// Release reporting helpers (no dependencies; Node >= 22).
//
//   node report.mjs sbom-count <sbom.cdx.json>                     -> prints the component count
//   node report.mjs vuln-summary <grype.json> <out-summary.json>   -> writes counts per severity, prints Critical/High
//   node report.mjs manifest <release-dir>                         -> writes <release-dir>/manifest.json
//   node report.mjs notes <CHANGELOG.md> <version> <release-dir>   -> prints release-notes.md
//
// Inputs written by release.sh into <release-dir>/.meta/: images.tsv, timings.tsv, release.env (KEY=VALUE).
import { existsSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const SEVERITIES = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"];

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function readTsv(path, columns) {
  if (!existsSync(path)) return [];
  return readFileSync(path, "utf8")
    .split(/\r?\n/)
    .filter((l) => l.trim() !== "")
    .map((l) => Object.fromEntries(l.split("\t").map((v, i) => [columns[i] ?? `c${i}`, v])));
}

function readEnv(path) {
  if (!existsSync(path)) return {};
  return Object.fromEntries(
    readFileSync(path, "utf8")
      .split(/\r?\n/)
      .filter((l) => /^[A-Z0-9_]+=/.test(l))
      .map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1)]),
  );
}

function sbomCount(path) {
  const sbom = readJson(path);
  return Array.isArray(sbom.components) ? sbom.components.length : 0;
}

function vulnSummary(path) {
  const report = readJson(path);
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
  const top = [];
  const seen = new Set();
  for (const m of report.matches ?? []) {
    const v = m.vulnerability ?? {};
    const sev = SEVERITIES.includes(v.severity) ? v.severity : "Unknown";
    const key = `${v.id}|${m.artifact?.name}|${m.artifact?.version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    counts[sev] += 1;
    if (sev === "Critical" || sev === "High") {
      const fixed = v.fix?.versions?.length ? v.fix.versions.join(",") : "no fix";
      top.push({ severity: sev, id: v.id, package: m.artifact?.name, version: m.artifact?.version, type: m.artifact?.type, fixed });
    }
  }
  top.sort((a, b) => (a.severity === b.severity ? String(a.id).localeCompare(String(b.id)) : a.severity === "Critical" ? -1 : 1));
  return { counts, top, dbBuilt: report.descriptor?.db?.built ?? report.descriptor?.db?.status?.built ?? null };
}

function fmtBytes(n) {
  const b = Number(n);
  if (!Number.isFinite(b)) return String(n);
  return b >= 1024 ** 3 ? `${(b / 1024 ** 3).toFixed(2)} GiB` : `${(b / 1024 ** 2).toFixed(1)} MiB`;
}

function manifest(dir) {
  const meta = join(dir, ".meta");
  const env = readEnv(join(meta, "release.env"));
  const images = readTsv(join(meta, "images.tsv"), ["name", "ref", "id", "size", "file", "pushed", "archiveSize"]).map((img) => {
    const sbomFile = `sbom/${img.name}-${env.VERSION}.cdx.json`;
    const scanFile = `scans/${img.name}-${env.VERSION}.summary.json`;
    return {
      name: img.name,
      ref: img.ref,
      imageId: img.id,
      sizeBytes: Number(img.size),
      archive: img.file || null,
      archiveBytes: Number(img.archiveSize) || null,
      pushed: img.pushed || null,
      sbom: existsSync(join(dir, sbomFile)) ? { file: sbomFile, components: sbomCount(join(dir, sbomFile)) } : null,
      vulnerabilities: existsSync(join(dir, scanFile)) ? readJson(join(dir, scanFile)).counts : null,
    };
  });
  const timings = readTsv(join(meta, "timings.tsv"), ["step", "seconds"]).map((t) => ({ step: t.step, seconds: Number(t.seconds) }));
  const bundles = existsSync(join(dir, "bundles")) ? readdirSync(join(dir, "bundles")).sort() : [];
  const out = {
    product: "PatchGate",
    version: env.VERSION,
    gitSha: env.GIT_SHA || null,
    createdAt: env.CREATED,
    connectorVersion: env.CONNECTOR_VERSION,
    protocolVersion: Number(env.PROTOCOL_VERSION) || null,
    qualityGate: { integration: env.INTEGRATION, connectorVersionSkew: env.VERSION_SKEW === "1", dirtyTree: env.DIRTY === "1" },
    siteBundle: env.SITE_BUNDLE || "skipped",
    signing: env.SIGNING || "none",
    vulnerabilityGate: { criticalTotal: Number(env.CRITICAL_TOTAL) || 0, overridden: env.ALLOW_VULNS === "1" },
    tools: Object.fromEntries(Object.entries(env).filter(([k]) => k.startsWith("TOOL_")).map(([k, v]) => [k.slice(5).toLowerCase(), v])),
    images,
    bundles,
    timings,
  };
  writeFileSync(join(dir, "manifest.json"), `${JSON.stringify(out, null, 2)}\n`);
  return out;
}

function changelogSection(changelog, version) {
  const lines = readFileSync(changelog, "utf8").split(/\r?\n/);
  const esc = version.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const start = lines.findIndex((l) => new RegExp(`^## \\[?v?${esc}\\]?(\\s|$)`).test(l));
  if (start < 0) return null;
  let end = lines.findIndex((l, i) => i > start && /^## /.test(l));
  if (end < 0) end = lines.length;
  return lines.slice(start + 1, end).join("\n").trim();
}

function notes(changelog, version, dir) {
  const section = changelogSection(changelog, version);
  if (section === null) throw new Error(`CHANGELOG.md has no "## [${version}]" section`);
  const m = existsSync(join(dir, "manifest.json")) ? readJson(join(dir, "manifest.json")) : manifest(dir);
  const out = [];
  out.push(`# PatchGate ${version}`, "");
  out.push(`Git commit: ${m.gitSha ?? "n/a (built outside git)"} · built ${m.createdAt} · connector ${m.connectorVersion} · connector protocol v${m.protocolVersion}`, "");
  out.push(section, "");
  out.push("## Artifacts", "");
  out.push("| Image | Image size | Archive | SBOM components | Critical | High | Medium |", "|---|---:|---:|---:|---:|---:|---:|");
  for (const i of m.images) {
    const v = i.vulnerabilities ?? {};
    const pushed = i.pushed ? `<br>\`${i.pushed}\`` : "";
    const archive = i.archiveBytes ? fmtBytes(i.archiveBytes) : "n/a";
    out.push(`| \`${i.ref}\`${pushed} | ${fmtBytes(i.sizeBytes)} | ${archive} | ${i.sbom?.components ?? "n/a"} | ${v.Critical ?? "n/a"} | ${v.High ?? "n/a"} | ${v.Medium ?? "n/a"} |`);
  }
  if (m.vulnerabilityGate?.overridden && m.vulnerabilityGate.criticalTotal > 0) {
    out.push("", `> WARNING: released with --allow-vulns: ${m.vulnerabilityGate.criticalTotal} CRITICAL findings (scans/*.summary.json). Record the reason in the changelog section above.`);
  }
  out.push("");
  if (m.bundles.length) out.push("Bundles: " + m.bundles.map((b) => `\`${b}\``).join(", "), "");
  out.push("## Verify and install", "");
  out.push("```bash", "sha256sum -c SHA256SUMS            # every file in this release", `docker load -i images/patchgate-web-${version}.tar.gz   # (and the other images)`, "```", "");
  out.push(`Signing: ${m.signing}. Upgrade order: server (backup → migrate → web-1 → web-2 → fetcher → scheduler), then connectors, then site bundles — see docs/RELEASE.md.`, "");
  if (m.qualityGate.connectorVersionSkew) out.push("> WARNING: built with --allow-version-skew (connector version differs from VERSION). Not for production.", "");
  return out.join("\n");
}

const [cmd, ...args] = process.argv.slice(2);
try {
  if (cmd === "sbom-count") {
    console.log(sbomCount(args[0]));
  } else if (cmd === "vuln-summary") {
    const s = vulnSummary(args[0]);
    writeFileSync(args[1], `${JSON.stringify(s, null, 2)}\n`);
    console.log(SEVERITIES.map((k) => `${k}=${s.counts[k]}`).join(" "));
    for (const t of s.top.slice(0, 25)) console.log(`      ${t.severity.padEnd(8)} ${String(t.id).padEnd(20)} ${t.package}@${t.version} (${t.type}) fixed: ${t.fixed}`);
    if (s.top.length > 25) console.log(`      … ${s.top.length - 25} more Critical/High in the JSON report`);
  } else if (cmd === "manifest") {
    manifest(args[0]);
  } else if (cmd === "notes") {
    process.stdout.write(`${notes(args[0], args[1], args[2])}\n`);
  } else if (cmd === "changelog-has") {
    process.exit(changelogSection(args[0], args[1]) === null ? 1 : 0);
  } else {
    console.error("usage: report.mjs sbom-count|vuln-summary|manifest|notes|changelog-has …");
    process.exit(2);
  }
} catch (err) {
  console.error(`report.mjs ${cmd}: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
}
