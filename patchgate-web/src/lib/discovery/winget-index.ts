import "server-only";
import { createWriteStream } from "node:fs";
import { mkdir, rename, rm, stat } from "node:fs/promises";
import { resolve } from "node:path";
import { pipeline } from "node:stream/promises";
import { DatabaseSync } from "node:sqlite";
import yauzl from "yauzl";
import { safeDownload } from "@/lib/fetch/http";
import { discardTemp, newTempFile } from "@/lib/fetch/repo";
import { verifyAuthenticode } from "@/lib/fetch/signature";
import { MAX_NAME_CANDIDATES, type CatalogLookup } from "./match";

/**
 * Local copy of the winget source index (the same SQLite file the winget client uses), used ONLY to
 * suggest which winget package an installed product is. It never decides what gets installed: every
 * package is still hash- and signer-verified on download and approved by people.
 */

export const WINGET_INDEX_URL = "https://cdn.winget.microsoft.com/cache/source.msix";
const WINGET_INDEX_HOSTS = ["cdn.winget.microsoft.com"];
const INDEX_SIGNER = "O=Microsoft Corporation";
const MAX_MSIX_BYTES = 200 * 1024 * 1024;
const MAX_DB_BYTES = 600 * 1024 * 1024;
const ENTRY = "Public/index.db";
const CATALOG_DIR = ".catalog"; // beside the served roots; not servable (leading dot)

export function indexPath(repoDir: string): string {
  return resolve(repoDir, CATALOG_DIR, "winget-index.db");
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
export async function refreshWingetIndex(opts: { repoDir: string; timeoutMs: number; codesignCaFile?: string }): Promise<IndexRefreshResult> {
  // Windows picks the signature format (SIP) by extension: an extensionless MSIX reads as "UnknownError".
  const msix = `${await newTempFile(opts.repoDir)}.msix`;
  const db = await newTempFile(opts.repoDir);
  try {
    await safeDownload(WINGET_INDEX_URL, msix, { allowedHosts: WINGET_INDEX_HOSTS, timeoutMs: opts.timeoutMs, maxBytes: MAX_MSIX_BYTES });
    const sig = await verifyAuthenticode(msix, INDEX_SIGNER, { codesignCaFile: opts.codesignCaFile });
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
