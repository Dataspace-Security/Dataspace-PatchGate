import "server-only";
import { readdir, stat } from "node:fs/promises";
import { join, resolve } from "node:path";
import { prisma } from "@/lib/db";
import { env } from "@/lib/env";
import { appendAudit } from "@/lib/audit/service";

/**
 * Shared repository quota (REPO_MAX_GB): the repository on disk is shared by every bank, and what lands in
 * it is driven by bank-side reports (Windows update GUIDs) and bank choices (managed apps). Above the quota
 * PatchGate downloads nothing more for Windows updates; queued files wait (never rejected).
 *
 * Monitoring signal: every check is recorded as a FetchRun (source "repo-quota", ok=false when exceeded,
 * shown with the other fetch runs) and each transition (exceeded / back under quota) is audited on the
 * platform chain → SIEM alert. repoQuotaStatus() is the cheap read for readiness / dashboards.
 */

export const REPO_QUOTA_SOURCE = "repo-quota";
const GIB = 1024 ** 3;

export interface RepoQuota {
  usedBytes: number;
  quotaBytes: number;
  freeBytes: number;
  exceeded: boolean;
}

/** Total size of every file under the repository root (served tree, staging, pending). */
export async function repoUsageBytes(root: string): Promise<number> {
  const base = resolve(root);
  let entries;
  try {
    entries = await readdir(base, { recursive: true, withFileTypes: true });
  } catch (err: unknown) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return 0;
    throw err;
  }
  let total = 0;
  for (const e of entries) {
    if (!e.isFile()) continue;
    const s = await stat(join(e.parentPath, e.name)).catch(() => null);
    total += s?.size ?? 0;
  }
  return total;
}

export function quotaFrom(usedBytes: number, quotaBytes: number): RepoQuota {
  const freeBytes = Math.max(0, quotaBytes - usedBytes);
  return { usedBytes, quotaBytes, freeBytes, exceeded: freeBytes <= 0 };
}

/** Measure the repository against the quota, record it and audit a state change. */
export async function checkRepoQuota(quotaBytesOverride?: number): Promise<RepoQuota> {
  const e = env();
  const q = quotaFrom(await repoUsageBytes(e.REPO_DIR), quotaBytesOverride ?? e.REPO_MAX_GB * GIB);
  const last = await prisma.fetchRun.findFirst({ where: { source: REPO_QUOTA_SOURCE }, orderBy: { startedAt: "desc" }, select: { ok: true } });
  const now = new Date();
  const usedGb = (q.usedBytes / GIB).toFixed(2);
  const quotaGb = (q.quotaBytes / GIB).toFixed(2);
  await prisma.fetchRun.create({
    data: { source: REPO_QUOTA_SOURCE, startedAt: now, finishedAt: now, ok: !q.exceeded, message: `${usedGb} of ${quotaGb} GB used${q.exceeded ? " — QUOTA EXCEEDED, Windows update downloads paused" : ""}` },
  });
  const wasExceeded = last ? last.ok === false : false;
  if (q.exceeded !== wasExceeded) {
    await appendAudit({
      actor: "system:repo",
      action: q.exceeded ? "repo.quota_exceeded" : "repo.quota_ok",
      entity: "Repository",
      entityId: "-",
      payload: { usedBytes: q.usedBytes, quotaBytes: q.quotaBytes },
    });
  }
  return q;
}

/** Latest recorded quota state (null = never measured). For readiness / monitoring views. */
export async function repoQuotaStatus(): Promise<{ ok: boolean; message: string | null; at: Date } | null> {
  const last = await prisma.fetchRun.findFirst({ where: { source: REPO_QUOTA_SOURCE }, orderBy: { startedAt: "desc" } });
  return last ? { ok: last.ok === true, message: last.message, at: last.startedAt } : null;
}
