/**
 * LAB TOOL — third-party app matrix discovery (runs in the PatchGate/internet zone).
 * For each candidate app it uses PatchGate's REAL installer selection (selectInstaller) on the live
 * winget catalog for the LATEST and an OLDER version, downloads both, reads the actual Authenticode
 * signer organisation, and records every redirect host. Output: ../lab/apps/matrix.json + fixtures
 * (older installers = "outdated software already on the bank PC").
 *
 *   GITHUB_TOKEN=$(gh auth token) npx tsx scripts/lab/discover-apps.ts
 */
import { execFileSync } from "node:child_process";
import { createWriteStream, existsSync, mkdirSync, statSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { installerManifestUrl, manifestDirFor, selectInstaller } from "../../src/lib/fetch/winget";
import { compareVersions } from "../../src/lib/thirdparty/version";

const CANDIDATES = process.env.ONLY ? process.env.ONLY.split(",") : [
  "Microsoft.PowerShell",
  "Git.Git",
  "7zip.7zip",
  "Notepad++.Notepad++",
  "VideoLAN.VLC",
  "EclipseAdoptium.Temurin.21.JRE",
  "Zoom.Zoom",
  "PuTTY.PuTTY",
  "WiresharkFoundation.Wireshark",
  "Mozilla.Firefox",
  "Google.Chrome",
];
const OLDER_STEPS_BACK = 3;
const OUT = resolve(__dirname, "../../../lab/apps");
const CACHE = join(OUT, "cache");
mkdirSync(CACHE, { recursive: true });

const gh = process.env.GITHUB_TOKEN ? { Authorization: `Bearer ${process.env.GITHUB_TOKEN}` } : undefined;

async function versionsOf(id: string): Promise<string[]> {
  const r = await fetch(`https://api.github.com/repos/microsoft/winget-pkgs/contents/${manifestDirFor(id)}`, { headers: gh });
  if (!r.ok) throw new Error(`listing ${id}: HTTP ${r.status}`);
  const items = (await r.json()) as { name: string; type: string }[];
  return items
    .filter((i) => i.type === "dir" && /^\d/.test(i.name))
    .map((i) => i.name)
    .sort(compareVersions);
}

/** Download following redirects manually so we can record every host (→ allowedDomains). */
async function download(url: string, dest: string): Promise<{ sha256: string; size: number; hosts: string[] }> {
  const hosts: string[] = [];
  let current = url;
  for (let hop = 0; hop < 6; hop++) {
    hosts.push(new URL(current).hostname);
    const res = await fetch(current, { redirect: "manual", headers: { "User-Agent": "Dataspace-PatchGate-lab" } });
    if (res.status >= 300 && res.status < 400) {
      current = new URL(res.headers.get("location")!, current).toString();
      continue;
    }
    if (!res.ok || !res.body) throw new Error(`HTTP ${res.status}`);
    if (!existsSync(dest)) await pipeline(Readable.fromWeb(res.body as never), createWriteStream(dest));
    else await res.body.cancel();
    const hash = execFileSync("powershell.exe", ["-NoProfile", "-Command", `(Get-FileHash -Algorithm SHA256 -LiteralPath '${dest}').Hash.ToLower()`]).toString().trim();
    return { sha256: hash, size: statSync(dest).size, hosts: [...new Set(hosts)] };
  }
  throw new Error("too many redirects");
}

function signerOrg(file: string): { status: string; org: string | null } {
  const ps =
    `$s = Get-AuthenticodeSignature -LiteralPath '${file}'; ` +
    `$o = if ($s.SignerCertificate) { ($s.SignerCertificate.SubjectName.Decode([System.Security.Cryptography.X509Certificates.X500DistinguishedNameFlags]::UseNewLines) -split "\`r?\`n" | Where-Object { $_ -like 'O=*' } | Select-Object -First 1) } else { '' }; ` +
    `"$($s.Status)|$o"`;
  const [status, org] = execFileSync("powershell.exe", ["-NoProfile", "-Command", ps]).toString().trim().split("|");
  return { status, org: org ? org.trim().replace(/^O=/, "").replace(/^"|"$/g, "") : null };
}

interface Side {
  version: string;
  kind?: string;
  installerType?: string;
  switches?: string;
  url?: string;
  manifestSha256?: string;
  downloadSha256?: string;
  hashMatches?: boolean;
  sizeMB?: number;
  signature?: string;
  org?: string | null;
  hosts?: string[];
  file?: string;
  error?: string;
}

async function side(id: string, version: string): Promise<Side> {
  const s: Side = { version };
  try {
    const manifest = await (await fetch(installerManifestUrl(id, version))).text();
    const inst = selectInstaller(manifest);
    if (!inst) return { ...s, error: "no installer PatchGate accepts (needs machine-scope MSI or EXE with safe switches)" };
    Object.assign(s, { kind: inst.kind, installerType: inst.installerType, switches: inst.switches, url: inst.url, manifestSha256: inst.sha256 });
    const file = join(CACHE, `${id}-${version}.${inst.kind}`);
    const dl = await download(inst.url, file);
    const sig = signerOrg(file);
    return {
      ...s,
      file,
      downloadSha256: dl.sha256,
      hashMatches: dl.sha256 === inst.sha256,
      sizeMB: Math.round(dl.size / 1e5) / 10,
      hosts: dl.hosts,
      signature: sig.status,
      org: sig.org,
    };
  } catch (err: unknown) {
    return { ...s, error: err instanceof Error ? err.message : String(err) };
  }
}

async function main() {
  const matrix: Record<string, { latest: Side; older: Side }> = {};
  for (const id of CANDIDATES) {
    process.stdout.write(`${id} ... `);
    try {
      const versions = await versionsOf(id);
      const latest = versions[versions.length - 1];
      const older = versions[Math.max(0, versions.length - 1 - OLDER_STEPS_BACK)];
      matrix[id] = { latest: await side(id, latest), older: await side(id, older) };
      const l = matrix[id].latest;
      console.log(l.error ? `latest ${latest}: ${l.error}` : `latest ${latest} ${l.kind}/${l.installerType} hash=${l.hashMatches} sig=${l.signature} O=${l.org}`);
    } catch (err: unknown) {
      console.log(`FAILED ${err instanceof Error ? err.message : err}`);
    }
  }
  const file = join(OUT, process.env.ONLY ? "matrix-extra.json" : "matrix.json");
  writeFileSync(file, JSON.stringify(matrix, null, 2));
  console.log(`\nwrote ${file}`);
}

void main();
