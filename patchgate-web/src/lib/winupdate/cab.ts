import "server-only";
import { rm } from "node:fs/promises";
import type { Prisma } from "@prisma/client";
import { prisma } from "@/lib/db";
import { env } from "@/lib/env";
import { appendAudit } from "@/lib/audit/service";
import type { JobPackage } from "@/lib/connector/protocol";
import { safeDownload } from "@/lib/fetch/http";
import { orgMatches } from "@/lib/fetch/dn";
import { discardTemp, newTempFile, publishFile, repoAbsPath } from "@/lib/fetch/repo";
import { readAuthenticode, type SignatureResult } from "@/lib/fetch/signature";
import { FETCH_HOSTS, MICROSOFT_PUBLISHER, WSUSSCN2_URL, scanCabRepoPath, scanCabVersion } from "./microsoft";
import { probeHead, type RemoteValidators } from "./probe";

/**
 * Microsoft offline scan catalog (wsusscn2.cab, ~700 MB, re-published by Microsoft around Patch Tuesday):
 * HEAD check → download only when the validators changed → SHA-256 + Authenticode (exact O=Microsoft
 * Corporation) → content-addressed publish under winupdate/wsusscan/. It is metadata (no code runs from it
 * on the PC besides Windows Update Agent itself), so there is no quarantine soak.
 */

const MAX_CAB_BYTES = 4 * 1024 ** 3;
const KEEP_VERIFIED = 2;
export const SCAN_CAB_SOURCE = "wsusscan";
export const SCAN_CAB_PACKAGE_ID = "Microsoft.WsusScan";

export interface CabDeps {
  probe: (url: string) => Promise<RemoteValidators>;
  download: (url: string, dest: string) => Promise<{ sha256: string; size: number }>;
  readSignature: (path: string) => Promise<SignatureResult>;
}

export function defaultCabDeps(): CabDeps {
  const e = env();
  return {
    probe: (url) => probeHead(url, { allowedHosts: FETCH_HOSTS, timeoutMs: 30_000 }),
    download: (url, dest) =>
      safeDownload(url, dest, { allowedHosts: FETCH_HOSTS, redirects: "allowlist", timeoutMs: e.FETCH_TIMEOUT_MS, maxBytes: Math.min(e.FETCH_MAX_BYTES, MAX_CAB_BYTES) }),
    readSignature: (path) => readAuthenticode(path, { codesignCaFile: e.CODESIGN_CA_FILE }),
  };
}

export type CabFetchResult =
  | { status: "up-to-date"; sha256: string }
  | { status: "published"; sha256: string; size: number }
  | { status: "rejected"; reason: string }
  | { status: "failed"; reason: string };

const sameValidators = (a: { etag: string | null; lastModified: string | null }, b: RemoteValidators) =>
  (a.etag ?? null) === b.etag && (a.lastModified ?? null) === b.lastModified && (a.etag !== null || a.lastModified !== null);

/** Check Microsoft for a new wsusscn2.cab and publish it if it verifies. Network outside any DB transaction. */
export async function fetchScanCab(deps: CabDeps = defaultCabDeps(), url = WSUSSCN2_URL): Promise<CabFetchResult> {
  const root = env().REPO_DIR;
  const run = await prisma.fetchRun.create({ data: { source: SCAN_CAB_SOURCE } });
  const finish = async (r: CabFetchResult): Promise<CabFetchResult> => {
    await prisma.fetchRun.update({
      where: { id: run.id },
      data: { finishedAt: new Date(), ok: r.status === "up-to-date" || r.status === "published", message: "reason" in r ? `${r.status}: ${r.reason}` : `${r.status} ${r.sha256.slice(0, 16)}` },
    });
    if (r.status === "published" || r.status === "rejected") {
      await appendAudit({
        actor: "system:winupdate",
        action: `winupdate.scan_cab.${r.status}`,
        entity: "WsusScanCab",
        entityId: "sha256" in r ? r.sha256 : "-",
        payload: { url, ...("reason" in r ? { reason: r.reason } : { sha256: r.sha256, size: r.size }) },
      });
    }
    return r;
  };

  let validators: RemoteValidators;
  try {
    validators = await deps.probe(url);
  } catch (err: unknown) {
    return finish({ status: "failed", reason: errText(err) });
  }
  const known = await prisma.wsusScanCab.findMany({ orderBy: { createdAt: "desc" }, take: 20 });
  const match = known.find((k) => sameValidators(k, validators));
  if (match?.verification === "VERIFIED") return finish({ status: "up-to-date", sha256: match.sha256 });
  if (match?.verification === "REJECTED") return finish({ status: "rejected", reason: `unchanged since rejection: ${match.rejectReason ?? "rejected"}` });

  const tmp = await newTempFile(root);
  try {
    let dl: { sha256: string; size: number };
    try {
      dl = await deps.download(url, tmp);
    } catch (err: unknown) {
      return finish({ status: "failed", reason: errText(err) });
    }
    const existing = await prisma.wsusScanCab.findUnique({ where: { sha256: dl.sha256 } });
    if (existing) {
      // Same bytes, new HTTP validators (CDN re-publish): remember them, keep the existing decision.
      await prisma.wsusScanCab.update({ where: { id: existing.id }, data: { etag: validators.etag, lastModified: validators.lastModified } });
      return finish(existing.verification === "VERIFIED" ? { status: "up-to-date", sha256: dl.sha256 } : { status: "rejected", reason: existing.rejectReason ?? "rejected" });
    }

    const sig = await deps.readSignature(tmp);
    const reason = !sig.ok ? sig.reason : orgMatches(sig.subject, MICROSOFT_PUBLISHER) ? null : `publisher mismatch (${sig.subject.slice(0, 200)})`;
    const base = { sha256: dl.sha256, sizeBytes: BigInt(dl.size), sourceUrl: url, etag: validators.etag, lastModified: validators.lastModified, signerSubject: sig.ok ? sig.subject.slice(0, 1000) : null };
    if (reason) {
      await prisma.wsusScanCab.create({ data: { ...base, verification: "REJECTED", rejectReason: reason.slice(0, 500) } });
      return finish({ status: "rejected", reason });
    }

    const repoPath = scanCabRepoPath(dl.sha256);
    await publishFile(root, tmp, repoPath);
    await prisma.wsusScanCab.create({ data: { ...base, verification: "VERIFIED", repoPath } });
    await pruneOldCabs(root);
    return finish({ status: "published", sha256: dl.sha256, size: dl.size });
  } finally {
    await discardTemp(tmp);
  }
}

/** Keep the newest verified catalogs on disk (sites may still be caching the previous one). */
async function pruneOldCabs(root: string): Promise<void> {
  const old = await prisma.wsusScanCab.findMany({ where: { verification: "VERIFIED", repoPath: { not: null } }, orderBy: { createdAt: "desc" }, skip: KEEP_VERIFIED });
  for (const c of old) {
    if (!c.repoPath) continue;
    await rm(repoAbsPath(root, c.repoPath), { force: true });
    await prisma.wsusScanCab.update({ where: { id: c.id }, data: { repoPath: null } });
  }
}

/** Latest verified catalog as a job package (kind wsusscan), or null if none has been verified yet. */
export async function latestScanCabPackage(tx: Prisma.TransactionClient): Promise<JobPackage | null> {
  const c = await tx.wsusScanCab.findFirst({ where: { verification: "VERIFIED", repoPath: { not: null } }, orderBy: { createdAt: "desc" } });
  if (!c?.repoPath) return null;
  return {
    kind: "wsusscan",
    wingetId: SCAN_CAB_PACKAGE_ID,
    version: scanCabVersion(c.createdAt, c.sha256),
    sha256: c.sha256,
    size: Number(c.sizeBytes),
    repoPath: c.repoPath,
    publisher: MICROSOFT_PUBLISHER,
    switches: "",
  };
}

export function errText(err: unknown): string {
  return (err instanceof Error ? err.message : "unknown error").replace(/[\r\n]+/g, " ").slice(0, 300);
}
