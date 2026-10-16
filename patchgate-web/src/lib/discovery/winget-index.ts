import "server-only";
import { createWriteStream } from "node:fs";
import { mkdir, readFile, rename, rm, stat, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pipeline } from "node:stream/promises";
import { DatabaseSync } from "node:sqlite";
import yauzl from "yauzl";
import { safeDownload } from "@/lib/fetch/http";
import { discardTemp, newTempFile } from "@/lib/fetch/repo";
import { filterCaBundle, isRootOf, verifyAuthenticode, type AuthenticodeOptions, type SignatureResult } from "@/lib/fetch/signature";
import { MAX_NAME_CANDIDATES, type CatalogLookup } from "./match";

/**
 * Local copy of the winget source index (the same SQLite file the winget client uses), used ONLY to
 * suggest which winget package an installed product is. It never decides what gets installed: every
 * package is still hash- and signer-verified on download and approved by people.
 */

export const WINGET_INDEX_URL = "https://cdn.winget.microsoft.com/cache/source.msix";
const WINGET_INDEX_HOSTS = ["cdn.winget.microsoft.com"];
const INDEX_ROOT_ORG = "Microsoft Corporation";
const INDEX_SIGNER = `O=${INDEX_ROOT_ORG}`;
const MAX_MSIX_BYTES = 200 * 1024 * 1024;
const MAX_DB_BYTES = 600 * 1024 * 1024;
const ENTRY = "Public/index.db";
const CATALOG_DIR = ".catalog"; // beside the served roots; not servable (leading dot)

export function indexPath(repoDir: string): string {
  return resolve(repoDir, CATALOG_DIR, "winget-index.db");
}

/**
 * Verify the index package: Authenticode (APPX) signature valid, signer organisation pinned to
 * "Microsoft Corporation", and — on Linux — signing chain AND timestamp chain anchored ONLY in the
 * self-signed Microsoft roots of CODESIGN_CA_FILE (other vendors' roots in the bundle are not trusted
 * for this file). Real chain (2026): Microsoft Corporation ← Microsoft Marketplace CA G 0xx ←
 * Microsoft MarketPlace PCA 2011 ← Microsoft Root Certificate Authority 2011; timestamp ← Microsoft
 * Time-Stamp PCA 2010 ← Microsoft Root Certificate Authority 2010. The leaf carries Microsoft's
 * critical Application Policies extension (osslsigncode is patched to accept it — Dockerfile).
 * `scratch` = path for the temporary Microsoft-only CA bundle (removed afterwards).
 */
export async function verifyIndexSignature(msix: string, opts: { codesign?: AuthenticodeOptions; scratch: string }): Promise<SignatureResult> {
  const codesign = opts.codesign ?? {};
  if (process.platform === "win32" || !codesign.codesignCaFile) return verifyAuthenticode(msix, INDEX_SIGNER, codesign);
  const roots = filterCaBundle(await readFile(codesign.codesignCaFile, "utf8"), isRootOf(INDEX_ROOT_ORG));
  if (roots.count === 0) return { ok: false, reason: "CODESIGN_CA_FILE contains no Microsoft root CA (RUNBOOK §4.4)" };
  await writeFile(opts.scratch, roots.pem, { flag: "wx", mode: 0o600 });
  try {
    return await verifyAuthenticode(msix, INDEX_SIGNER, { ...codesign, codesignCaFile: opts.scratch, tsaCaFile: opts.scratch });
  } finally {
    await rm(opts.scratch, { force: true });
  }
}

/** Extract one entry from a zip (msix) with a hard size cap. */
async function extractEntry(zipPath: string, entryName: string, dest: string, maxBytes: number): Promise<void> {
  const zip = await new Promise<yauzl.ZipFile>((ok, ko) =>
    yauzl.open(zipPath, { lazyEntries: true, autoClose: true, strictFileNames: true }, (err, z) => (err || !z ? ko(err ?? new Error("zip open failed")) : ok(z))),
  );
  try {
    const entry = await new Promise<yauzl.Entry>((ok, ko) => {
      zip.on("entry", (e: yauzl.Entry) => (e.fileName === entryName ? ok(e) : zip.readEntry()));
      zip.on("end", () => ko(new Error(`${entryName} not found in catalog package`)));
      zip.on("error", ko);
      zip.readEntry();
    });
    if (entry.uncompressedSize > maxBytes) throw new Error("catalog index exceeds size limit");
    const stream = await new Promise<NodeJS.ReadableStream>((ok, ko) => zip.openReadStream(entry, (err, s) => (err || !s ? ko(err ?? new Error("zip read failed")) : ok(s))));
    // yauzl validates the actual inflated size against the header (fails on mismatch).
    await pipeline(stream, createWriteStream(dest, { flags: "wx", mode: 0o600 }));
  } finally {
    zip.close();
  }
}

/** Sanity check: the tables discovery relies on exist and are populated. */
function assertIndexShape(dbPath: string): number {
  const db = new DatabaseSync(dbPath, { readOnly: true });
  try {
    for (const t of ["manifest", "ids", "productcodes", "productcodes_map", "norm_names", "norm_names_map", "norm_publishers", "norm_publishers_map"]) {
      const row = db.prepare("SELECT 1 AS ok FROM sqlite_master WHERE type = 'table' AND name = ?").get(t);
      if (!row) throw new Error(`catalog index is missing table ${t}`);
    }
    const { n } = db.prepare("SELECT COUNT(*) AS n FROM ids").get() as { n: number };
    if (n < 1000) throw new Error("catalog index looks truncated");
    return n;
  } finally {
    db.close();
  }
}

export interface IndexRefreshResult {
  packages: number;
  bytes: number;
}

/** Download + verify (Microsoft signature) + extract + validate + atomically replace the index. */
export async function refreshWingetIndex(opts: { repoDir: string; timeoutMs: number; codesign?: AuthenticodeOptions }): Promise<IndexRefreshResult> {
  // Windows picks the signature format (SIP) by extension: an extensionless MSIX reads as "UnknownError".
  const msix = `${await newTempFile(opts.repoDir)}.msix`;
  const db = await newTempFile(opts.repoDir);
  try {
    await safeDownload(WINGET_INDEX_URL, msix, { allowedHosts: WINGET_INDEX_HOSTS, timeoutMs: opts.timeoutMs, maxBytes: MAX_MSIX_BYTES });
    const sig = await verifyIndexSignature(msix, { codesign: opts.codesign, scratch: `${db}.roots.pem` });
    if (!sig.ok) throw new Error(`catalog index signature: ${sig.reason}`);
    await extractEntry(msix, ENTRY, db, MAX_DB_BYTES);
    const packages = assertIndexShape(db);
    const dest = indexPath(opts.repoDir);
    await mkdir(resolve(dest, ".."), { recursive: true, mode: 0o700 });
    await rename(db, dest);
    return { packages, bytes: (await stat(dest)).size };
  } finally {
    await discardTemp(msix);
    await rm(db, { force: true });
  }
}

/** Open the local index for lookups; null when it hasn't been downloaded yet. */
export async function openCatalog(repoDir: string): Promise<(CatalogLookup & { close(): void }) | null> {
  const path = indexPath(repoDir);
  try {
    await stat(path);
  } catch {
    return null;
  }
  const db = new DatabaseSync(path, { readOnly: true });
  const byCode = db.prepare(
    `SELECT DISTINCT i.id AS id FROM productcodes p
       JOIN productcodes_map pm ON pm.productcode = p.rowid
       JOIN manifest m ON m.rowid = pm.manifest
       JOIN ids i ON i.rowid = m.id
      WHERE p.productcode = ?`,
  );
  const NAME_SLOTS = MAX_NAME_CANDIDATES;
  const byNames = db.prepare(
    `SELECT DISTINCT i.id AS id, np.norm_publisher AS publisher FROM norm_names n
       JOIN norm_names_map nm ON nm.norm_name = n.rowid
       JOIN manifest m ON m.rowid = nm.manifest
       JOIN ids i ON i.rowid = m.id
       LEFT JOIN norm_publishers_map pm ON pm.manifest = m.rowid
       LEFT JOIN norm_publishers np ON np.rowid = pm.norm_publisher
      WHERE n.norm_name IN (${Array(NAME_SLOTS).fill("?").join(",")})`,
  );
  const pubsOf = db.prepare(
    `SELECT DISTINCT np.norm_publisher AS publisher FROM ids i
       JOIN manifest m ON m.id = i.rowid
       JOIN norm_publishers_map pm ON pm.manifest = m.rowid
       JOIN norm_publishers np ON np.rowid = pm.norm_publisher
      WHERE i.id = ?`,
  );
  return {
    publishersOf: (id) => (pubsOf.all(id) as { publisher: string }[]).map((r) => r.publisher),
    idsByProductCode: (code) => (byCode.all(code) as { id: string }[]).map((r) => r.id),
    idsByNames: (names) => {
      const padded = [...names.slice(0, NAME_SLOTS)];
      while (padded.length < NAME_SLOTS) padded.push("\u0000");
      return byNames.all(...padded) as { id: string; publisher: string | null }[];
    },
    close: () => db.close(),
  };
}
