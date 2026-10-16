import "server-only";
import { rm } from "node:fs/promises";
import type { Prisma, WinUpdate } from "@prisma/client";
import { prisma } from "@/lib/db";
import { env } from "@/lib/env";
import { appendAudit } from "@/lib/audit/service";
import { repoAbsPath } from "@/lib/fetch/repo";
import { mapSeverity } from "@/lib/scan/map";
import { errText } from "./cab";
import { lookupCatalogUpdate, planCatalogBinding, type BoundFile, type CatalogLookup } from "./catalog";

/**
 * Fetch-loop step: bind PENDING updates (GUIDs reported by PC scans) to the Microsoft Update Catalog.
 * Exactly once per update, title/KB/severity/classification and the file set come from Microsoft, then the
 * binding is sealed (DB triggers refuse later changes). Legacy PC-reported files are reconciled: a file that
 * Microsoft lists with the same URL and whose verified bytes match the catalog SHA-256 is kept, every other
 * reported file is deleted (and its repository copy removed).
 */

type Tx = Prisma.TransactionClient;

export interface ResolveDeps {
  lookup: (updateId: string) => Promise<CatalogLookup>;
}

export const defaultResolveDeps = (): ResolveDeps => ({ lookup: (id) => lookupCatalogUpdate(id) });

const DEFAULT_MAX_PER_RUN = 40;
const NOT_FOUND_ATTEMPTS = 3; // then UNRESOLVABLE
const RETRY_BASE_MS = 60 * 60_000;
const RETRY_MAX_MS = 24 * 60 * 60_000;

export type ResolveOutcome = "resolved" | "unresolvable" | "retry";

const backoff = (attempts: number) => Math.min(RETRY_MAX_MS, RETRY_BASE_MS * 2 ** Math.max(0, attempts - 1));

async function retryLater(u: WinUpdate, reason: string, now: Date): Promise<ResolveOutcome> {
  const attempts = u.resolveAttempts + 1;
  await prisma.winUpdate.update({ where: { id: u.id }, data: { resolveAttempts: attempts, resolveError: reason.slice(0, 500), nextResolveAt: new Date(now.getTime() + backoff(attempts)) } });
  return "retry";
}

interface Meta {
  title: string | null;
  kb: string | null;
  msrcSeverity: string | null;
  classification: string | null;
}

async function writeMeta(tx: Tx, u: WinUpdate, meta: Meta): Promise<void> {
  const title = meta.title ?? u.title;
  await tx.patch.updateMany({
    where: { kind: "WINDOWS", externalId: u.id },
    data: { title, kb: meta.kb, severity: mapSeverity(meta.msrcSeverity), classification: meta.classification },
  });
}

async function seal(u: WinUpdate, reason: string, meta: Meta, now: Date): Promise<ResolveOutcome> {
  const removed = await prisma.$transaction(async (tx) => {
    const reported = await tx.winUpdateFile.findMany({ where: { updateId: u.id, source: "REPORTED" }, select: { id: true, repoPath: true } });
    await tx.winUpdateFile.deleteMany({ where: { id: { in: reported.map((r) => r.id) } } });
    await tx.winUpdate.update({
      where: { id: u.id },
      data: {
        catalogState: "UNRESOLVABLE",
        resolveAttempts: u.resolveAttempts + 1,
        resolveError: reason.slice(0, 500),
        resolvedAt: now,
        ...(meta.title ? { title: meta.title, kb: meta.kb, msrcSeverity: meta.msrcSeverity, classification: meta.classification } : {}),
      },
    });
    if (meta.title) await writeMeta(tx, u, meta);
    await appendAudit(
      { actor: "system:winupdate", action: "winupdate.update.unresolvable", entity: "WinUpdate", entityId: u.id, payload: { reason: reason.slice(0, 500), kb: meta.kb, removedReportedFiles: reported.length } },
      tx,
    );
    return reported.flatMap((r) => (r.repoPath ? [r.repoPath] : []));
  });
  await removeRepoFiles(removed);
  return "unresolvable";
}

async function bind(u: WinUpdate, b: Extract<ReturnType<typeof planCatalogBinding>, { ok: true }>, now: Date): Promise<ResolveOutcome> {
  const removed = await prisma.$transaction(async (tx) => {
    const reported = await tx.winUpdateFile.findMany({ where: { updateId: u.id, source: "REPORTED" } });
    const byUrl = new Map(reported.map((r) => [r.url, r]));
    const keep = new Set<string>();
    const create: (BoundFile & { updateId: string })[] = [];
    for (const f of b.files) {
      const r = byUrl.get(f.url);
      // A verified legacy download is kept only when its actual SHA-256 is the catalog's (proves the bytes).
      if (r && r.verification === "VERIFIED" && f.expectedSha256 && r.sha256 === f.expectedSha256) {
        await tx.winUpdateFile.update({ where: { id: r.id }, data: { source: "CATALOG", sha1: f.sha1, expectedSha256: f.expectedSha256, ordinal: f.ordinal, name: f.name, kind: f.kind } });
        keep.add(r.id);
      } else {
        create.push({ ...f, updateId: u.id });
      }
    }
    const drop = reported.filter((r) => !keep.has(r.id));
    await tx.winUpdateFile.deleteMany({ where: { id: { in: drop.map((r) => r.id) } } });
    if (create.length > 0) {
      await tx.winUpdateFile.createMany({
        data: create.map((f) => ({ updateId: f.updateId, url: f.url, name: f.name, kind: f.kind, ordinal: f.ordinal, sha1: f.sha1, expectedSha256: f.expectedSha256, source: "CATALOG" as const })),
      });
    }
    await tx.winUpdate.update({
      where: { id: u.id },
      data: { catalogState: "RESOLVED", title: b.title, kb: b.kb, msrcSeverity: b.msrcSeverity, classification: b.classification, resolvedAt: now, resolveError: null, resolveAttempts: u.resolveAttempts + 1 },
    });
    await writeMeta(tx, u, b);
    await appendAudit(
      {
        actor: "system:winupdate",
        action: "winupdate.update.resolved",
        entity: "WinUpdate",
        entityId: u.id,
        payload: { kb: b.kb, title: b.title.slice(0, 300), msrcSeverity: b.msrcSeverity, files: b.files.map((f) => ({ name: f.name, sha1: f.sha1 })), keptVerified: keep.size, removedReportedFiles: drop.length },
      },
      tx,
    );
    return drop.flatMap((r) => (r.repoPath ? [r.repoPath] : []));
  });
  await removeRepoFiles(removed);
  return "resolved";
}

/** Remove repository copies of dropped reported files unless a remaining row still points at the same path. */
async function removeRepoFiles(paths: string[]): Promise<void> {
  if (paths.length === 0) return;
  const root = env().REPO_DIR;
  const still = new Set((await prisma.winUpdateFile.findMany({ where: { repoPath: { in: paths } }, select: { repoPath: true } })).map((r) => r.repoPath));
  for (const p of paths) {
    if (still.has(p)) continue;
    try {
      await rm(repoAbsPath(root, p), { force: true });
    } catch {
      // unsafe/odd legacy path: leave it (the file is not referenced by any row, so it is never served to connectors)
    }
  }
}

/** Resolve ONE pending update (network lookup outside any transaction). */
export async function resolveUpdate(u: WinUpdate, deps: ResolveDeps = defaultResolveDeps(), now = new Date()): Promise<ResolveOutcome> {
  let found: CatalogLookup;
  try {
    found = await deps.lookup(u.id);
  } catch (err: unknown) {
    return retryLater(u, `catalog lookup failed: ${errText(err)}`, now);
  }
  if (!found.found) {
    if (u.resolveAttempts + 1 >= NOT_FOUND_ATTEMPTS) return seal(u, "not published in the Microsoft Update Catalog", { title: null, kb: null, msrcSeverity: null, classification: null }, now);
    return retryLater(u, "not found in the Microsoft Update Catalog", now);
  }
  const binding = planCatalogBinding(found);
  return binding.ok ? bind(u, binding, now) : seal(u, binding.reason, binding, now);
}

/** Worker step: resolve due PENDING updates (bounded per run). */
export async function resolvePendingUpdates(
  deps: ResolveDeps = defaultResolveDeps(),
  now = new Date(),
  maxPerRun = DEFAULT_MAX_PER_RUN,
): Promise<Record<ResolveOutcome, number>> {
  const due = await prisma.winUpdate.findMany({ where: { catalogState: "PENDING", nextResolveAt: { lte: now } }, orderBy: [{ nextResolveAt: "asc" }, { createdAt: "asc" }], take: maxPerRun });
  const out: Record<ResolveOutcome, number> = { resolved: 0, unresolvable: 0, retry: 0 };
  for (const u of due) {
    try {
      out[await resolveUpdate(u, deps, now)]++;
    } catch (err: unknown) {
      out[await retryLater(u, errText(err), now)]++;
    }
  }
  return out;
}
