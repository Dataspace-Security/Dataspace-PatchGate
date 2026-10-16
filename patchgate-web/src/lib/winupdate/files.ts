import "server-only";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { copyFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";
import type { WinUpdateFile } from "@prisma/client";
import { prisma } from "@/lib/db";
import { env } from "@/lib/env";
import { appendAudit } from "@/lib/audit/service";
import { orgMatches } from "@/lib/fetch/dn";
import { safeDownload } from "@/lib/fetch/http";
import { discardTemp, newTempFile, publishFile, realRepoFile, repoAbsPath } from "@/lib/fetch/repo";
import { readAuthenticode, type SignatureResult } from "@/lib/fetch/signature";
import { errText } from "./cab";
import { FETCH_HOSTS, MICROSOFT_PUBLISHER, normalizeUpdateUrl, updateFileRepoPath } from "./microsoft";
import { checkRepoQuota } from "./quota";

/**
 * Microsoft update file pipeline: PENDING rows (bound from the Microsoft Update Catalog by resolve.ts) → https download from the exact
 * Microsoft host allow-list → expected digest (SHA-1 Microsoft embeds in the name / the catalog reported,
 * SHA-256 if reported) + size + Authenticode (exact O=Microsoft Corporation) → publish under
 * winupdate/<updateId>/ → VERIFIED with a quarantine soak (QUARANTINE_HOURS) like third-party packages.
 * Verification failures are REJECTED with the reason (never retried); network failures back off and retry.
 */

/** Protocol cap for one package (Windows 11 cumulative updates are ~4 GB). Independent of FETCH_MAX_BYTES. */
export const WU_MAX_FILE_BYTES = 4 * 1024 ** 3;
/** All files of ONE update together (LCU + checkpoint LCU ~ 5 GB). Larger = undeliverable. */
export const WU_MAX_UPDATE_BYTES = 8 * 1024 ** 3;
const MAX_ATTEMPTS = 8;
const BACKOFF_BASE_MS = 60 * 60_000;
const BACKOFF_MAX_MS = 24 * 60 * 60_000;
const BUDGET_RETRY_MS = 60 * 60_000;
const DEFAULT_MAX_FILES = 25;
/** Per fetch run (hourly): bounds bandwidth and how fast the shared repository can grow. */
export const WU_MAX_RUN_BYTES = 20 * 1024 ** 3;

export interface FileDeps {
  /** maxBytes: the byte budget left for this file (never above WU_MAX_FILE_BYTES). */
  download: (url: string, dest: string, maxBytes: number) => Promise<{ sha256: string; size: number }>;
  readSignature: (path: string) => Promise<SignatureResult>;
}

export function defaultFileDeps(): FileDeps {
  const e = env();
  return {
    download: (url, dest, maxBytes) =>
      safeDownload(url, dest, { allowedHosts: FETCH_HOSTS, redirects: "allowlist", timeoutMs: e.FETCH_TIMEOUT_MS, maxBytes: Math.min(maxBytes, WU_MAX_FILE_BYTES) }),
    readSignature: (path) => readAuthenticode(path, { codesignCaFile: e.CODESIGN_CA_FILE }),
  };
}

async function sha1File(path: string): Promise<string> {
  const h = createHash("sha1");
  for await (const chunk of createReadStream(path)) h.update(chunk as Buffer);
  return h.digest("hex");
}

export type Verdict = { ok: true; signerSubject: string } | { ok: false; reason: string };

/** Pure decision on a downloaded file (the bytes' digests + signature against what the catalog said). */
export function judgeFile(
  f: Pick<WinUpdateFile, "sha1" | "expectedSha256" | "declaredSize">,
  actual: { sha1: string; sha256: string; size: number },
  sig: SignatureResult,
): Verdict {
  if (!f.sha1 && !f.expectedSha256) return { ok: false, reason: "no expected digest" };
  if (f.sha1 && f.sha1 !== actual.sha1) return { ok: false, reason: "SHA-1 differs from the catalog digest" };
  if (f.expectedSha256 && f.expectedSha256 !== actual.sha256) return { ok: false, reason: "SHA-256 differs from the catalog digest" };
  if (f.declaredSize !== null && f.declaredSize !== BigInt(actual.size)) return { ok: false, reason: `size ${actual.size} differs from the catalog (${f.declaredSize})` };
  if (!sig.ok) return { ok: false, reason: sig.reason };
  if (!orgMatches(sig.subject, MICROSOFT_PUBLISHER)) return { ok: false, reason: `publisher mismatch (${sig.subject.slice(0, 200)})` };
  return { ok: true, signerSubject: sig.subject.slice(0, 1000) };
}

/** Permanent = will not get better by retrying (wrong host, 404/410, size cap). */
export function isPermanentDownloadError(message: string): boolean {
  return /not allowed|Only https|Invalid URL|HTTP 4(?:0[0-4]|10)\b|exceeds size limit|non-public/i.test(message);
}

export type FileOutcome = "verified" | "rejected" | "retry" | "deferred";

async function reject(f: WinUpdateFile, reason: string): Promise<FileOutcome> {
  await prisma.winUpdateFile.update({ where: { id: f.id }, data: { verification: "REJECTED", rejectReason: reason.slice(0, 500), attempts: { increment: 1 } } });
  await appendAudit({ actor: "system:winupdate", action: "winupdate.file.rejected", entity: "WinUpdateFile", entityId: f.id, payload: { updateId: f.updateId, url: f.url, reason: reason.slice(0, 500) } });
  return "rejected";
}

async function retryLater(f: WinUpdateFile, reason: string, now: Date): Promise<FileOutcome> {
  const attempts = f.attempts + 1;
  if (attempts >= MAX_ATTEMPTS) return reject(f, `download failed ${attempts} times: ${reason}`);
  const delay = Math.min(BACKOFF_MAX_MS, BACKOFF_BASE_MS * 2 ** (attempts - 1));
  await prisma.winUpdateFile.update({ where: { id: f.id }, data: { attempts, lastError: reason.slice(0, 500), nextAttemptAt: new Date(now.getTime() + delay) } });
  return "retry";
}

async function markVerified(f: WinUpdateFile, data: { sha256: string; size: number; signerSubject: string; repoPath: string }, now: Date): Promise<void> {
  const availableAt = new Date(now.getTime() + env().QUARANTINE_HOURS * 3_600_000);
  await prisma.winUpdateFile.update({
    where: { id: f.id },
    data: { verification: "VERIFIED", sha256: data.sha256, sizeBytes: BigInt(data.size), signerSubject: data.signerSubject, repoPath: data.repoPath, verifiedAt: now, availableAt, lastError: null, attempts: { increment: 1 } },
  });
  await appendAudit({
    actor: "system:winupdate",
    action: "winupdate.file.verified",
    entity: "WinUpdateFile",
    entityId: f.id,
    payload: { updateId: f.updateId, url: f.url, sha256: data.sha256, size: data.size, signer: data.signerSubject.slice(0, 300), availableAt: availableAt.toISOString() },
  });
}

/** Same URL already verified for another update (bundles share payloads): copy instead of downloading again. */
async function reuseVerified(f: WinUpdateFile, root: string, repoPath: string, now: Date, limit: number): Promise<boolean> {
  const twin = await prisma.winUpdateFile.findFirst({ where: { url: f.url, verification: "VERIFIED", source: "CATALOG", repoPath: { not: null }, id: { not: f.id } } });
  if (!twin?.repoPath || !twin.sha256 || twin.sizeBytes === null || !twin.signerSubject) return false;
  if (Number(twin.sizeBytes) > limit) return false;
  if ((f.sha1 && twin.sha1 !== f.sha1) || (f.expectedSha256 && twin.sha256 !== f.expectedSha256)) return false;
  const src = await realRepoFile(root, twin.repoPath).catch(() => null);
  if (!src) return false;
  const dest = repoAbsPath(root, repoPath);
  await mkdir(dirname(dest), { recursive: true });
  await copyFile(src, dest);
  await markVerified(f, { sha256: twin.sha256, size: Number(twin.sizeBytes), signerSubject: twin.signerSubject, repoPath }, now);
  return true;
}

/** Bytes still allowed for this file by the repository quota and the per-run budget (both temporary limits). */
export interface FileBudget {
  transientBytes: number;
}

async function deferForBudget(f: WinUpdateFile, reason: string, now: Date): Promise<FileOutcome> {
  await prisma.winUpdateFile.update({ where: { id: f.id }, data: { lastError: reason.slice(0, 500), nextAttemptAt: new Date(now.getTime() + BUDGET_RETRY_MS) } });
  return "deferred";
}

/** Download + verify + publish ONE pending file. Network I/O happens outside any DB transaction. */
export async function processFile(
  f: WinUpdateFile,
  deps: FileDeps = defaultFileDeps(),
  now = new Date(),
  budget: FileBudget = { transientBytes: WU_MAX_FILE_BYTES },
): Promise<FileOutcome> {
  const root = env().REPO_DIR;
  if (f.source !== "CATALOG") return reject(f, "not bound from the Microsoft Update Catalog");
  const used = await prisma.winUpdateFile.aggregate({ where: { updateId: f.updateId, verification: "VERIFIED", id: { not: f.id } }, _sum: { sizeBytes: true } });
  const updateLeft = WU_MAX_UPDATE_BYTES - Number(used._sum.sizeBytes ?? BigInt(0));
  if (updateLeft <= 0) return reject(f, "update exceeds the per-update byte budget");
  const limit = Math.min(WU_MAX_FILE_BYTES, updateLeft, budget.transientBytes);
  if (limit <= 0) return deferForBudget(f, "deferred: repository quota / run byte budget exhausted", now);
  const u = normalizeUpdateUrl(f.url);
  if (!u.ok) return reject(f, u.reason);
  if (u.url !== f.url || u.kind !== f.kind) return reject(f, "stored URL is not in canonical form");
  let repoPath: string;
  try {
    repoPath = updateFileRepoPath(f.updateId, u.name);
  } catch {
    return reject(f, "unsafe repository path");
  }
  if (await reuseVerified(f, root, repoPath, now, limit)) return "verified";

  const tmp = await newTempFile(root);
  try {
    let dl: { sha256: string; size: number };
    try {
      dl = await deps.download(u.url, tmp, limit);
    } catch (err: unknown) {
      const msg = errText(err);
      if (/exceeds size limit/i.test(msg) && limit < WU_MAX_FILE_BYTES) {
        // The binding budget decides: the update's own budget is final, quota / run budget are temporary.
        if (limit === updateLeft) return reject(f, "update exceeds the per-update byte budget");
        return deferForBudget(f, "deferred: repository quota / run byte budget exhausted", now);
      }
      return isPermanentDownloadError(msg) ? reject(f, msg) : retryLater(f, msg, now);
    }
    const verdict = judgeFile(f, { sha1: await sha1File(tmp), sha256: dl.sha256, size: dl.size }, await deps.readSignature(tmp));
    if (!verdict.ok) return reject(f, verdict.reason);
    await publishFile(root, tmp, repoPath);
    await markVerified(f, { sha256: dl.sha256, size: dl.size, signerSubject: verdict.signerSubject, repoPath }, now);
    return "verified";
  } finally {
    await discardTemp(tmp);
  }
}

/**
 * Worker step: work through due PENDING catalog-bound files, bounded per run by count and bytes, and by the
 * shared repository quota (REPO_MAX_GB). At the quota nothing more is downloaded (files wait, they are not
 * rejected) and the run reports quotaExceeded (audited on each transition, see quota.ts).
 */
export async function processPendingFiles(
  deps: FileDeps = defaultFileDeps(),
  now = new Date(),
  limits: { maxFiles?: number; maxBytes?: number; quotaBytes?: number } = {},
): Promise<Record<FileOutcome, number> & { quotaExceeded: boolean }> {
  const maxFiles = limits.maxFiles ?? DEFAULT_MAX_FILES;
  const maxBytes = limits.maxBytes ?? WU_MAX_RUN_BYTES;
  const quota = await checkRepoQuota(limits.quotaBytes);
  const out: Record<FileOutcome, number> & { quotaExceeded: boolean } = { verified: 0, rejected: 0, retry: 0, deferred: 0, quotaExceeded: quota.exceeded };
  if (quota.exceeded) return out;
  const due = await prisma.winUpdateFile.findMany({
    where: { verification: "PENDING", source: "CATALOG", nextAttemptAt: { lte: now }, update: { catalogState: "RESOLVED" } },
    orderBy: [{ nextAttemptAt: "asc" }, { createdAt: "asc" }],
    take: maxFiles,
  });
  let bytes = 0;
  for (const f of due) {
    const transientBytes = Math.min(maxBytes - bytes, quota.freeBytes - bytes);
    if (transientBytes <= 0) break;
    try {
      out[await processFile(f, deps, now, { transientBytes })]++;
    } catch (err: unknown) {
      out[await retryLater(f, errText(err), now)]++;
    }
    const after = await prisma.winUpdateFile.findUnique({ where: { id: f.id }, select: { sizeBytes: true, verification: true } });
    if (after?.verification === "VERIFIED") bytes += Number(after.sizeBytes ?? 0);
  }
  return out;
}

/** For the connector package endpoint: a VERIFIED Windows-update file or scan catalog by SHA-256. */
export async function winupdatePackageBySha256(
  tx: Pick<typeof prisma, "winUpdateFile" | "wsusScanCab">,
  sha256: string,
  now = new Date(),
): Promise<{ repoPath: string; size: number } | null> {
  if (!/^[a-f0-9]{64}$/.test(sha256)) return null;
  const file = await tx.winUpdateFile.findFirst({
    where: { sha256, verification: "VERIFIED", source: "CATALOG", repoPath: { not: null }, availableAt: { lte: now }, update: { catalogState: "RESOLVED" } },
  });
  if (file?.repoPath && file.sizeBytes !== null) return { repoPath: file.repoPath, size: Number(file.sizeBytes) };
  const cab = await tx.wsusScanCab.findFirst({ where: { sha256, verification: "VERIFIED", repoPath: { not: null } } });
  if (cab?.repoPath) return { repoPath: cab.repoPath, size: Number(cab.sizeBytes) };
  return null;
}
