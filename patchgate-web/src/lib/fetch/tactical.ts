import "server-only";
import { mkdir, rename } from "node:fs/promises";
import { dirname } from "node:path";
import { z } from "zod";
import type { MirrorComponent } from "@prisma/client";
import { prisma } from "@/lib/db";
import { env } from "@/lib/env";
import { appendAudit } from "@/lib/audit/service";
import { DomainError } from "@/lib/errors";
import { safeDownload, safeFetchJson } from "./http";
import { discardTemp, newTempFile, pendingAbs, publishFile, repoAbsPath } from "./repo";
import { codesignOptions, verifyAuthenticode } from "./signature";
import { compareVersions } from "@/lib/thirdparty/version";
import { hasAllAgentArches } from "@/lib/thirdparty/package-from-db";

/**
 * Mirror Tactical RMM releases so the OFFLINE Tactical server/agents update only from PatchGate.
 * - Agent .exe: must match GitHub's published sha256 digest; Authenticode (AmidaWare) => VERIFIED,
 *   unsigned => PENDING (admin must approve; file is held outside the served tree).
 * - Server source tarball: no upstream digest => always PENDING (admin approval).
 */

export const GITHUB_HOSTS = [
  "api.github.com",
  "github.com",
  "codeload.github.com",
  "release-assets.githubusercontent.com",
  "objects.githubusercontent.com",
] as const;

const AGENT_ASSET = /^tacticalagent-v(\d+\.\d+\.\d+)-windows-(amd64|386)\.exe$/;
const TAG = /^v(\d+\.\d+\.\d+)$/;
const AGENT_PUBLISHER = "O=AmidaWare LLC"; // exact organisation pin

const releaseSchema = z.object({
  tag_name: z.string(),
  tarball_url: z.string(),
  assets: z.array(
    z.object({
      name: z.string(),
      size: z.number(),
      digest: z.string().nullish(),
      browser_download_url: z.string(),
    }),
  ),
});

function ghOpts() {
  const token = env().GITHUB_TOKEN;
  return {
    allowedHosts: [...GITHUB_HOSTS],
    timeoutMs: 30_000,
    authHeaders: token ? { host: "api.github.com", headers: { Authorization: `Bearer ${token}` } } : undefined,
  };
}

interface MirrorItem {
  component: MirrorComponent;
  version: string;
  assetName: string;
  url: string;
  expectedSha256: string | null;
  signedBy: string | null;
}

async function mirrorOne(item: MirrorItem): Promise<string> {
  const e = env();
  const exists = await prisma.mirroredRelease.findUnique({
    where: { component_version_assetName: { component: item.component, version: item.version, assetName: item.assetName } },
  });
  if (exists) return "up-to-date";

  const rel = `tactical/${item.component === "TACTICAL_AGENT" ? "agent" : "server"}/${item.version}/${item.assetName}`;
  const tmp = await newTempFile(e.REPO_DIR);
  try {
    const dl = await safeDownload(item.url, tmp, { ...ghOpts(), timeoutMs: e.FETCH_TIMEOUT_MS, maxBytes: e.FETCH_MAX_BYTES });

    let verification: "VERIFIED" | "PENDING" | "REJECTED" = "PENDING";
    let reason: string | null = "requires admin approval";
    if (item.expectedSha256 && dl.sha256 !== item.expectedSha256) {
      verification = "REJECTED";
      reason = `sha256 mismatch (GitHub ${item.expectedSha256}, got ${dl.sha256})`;
    } else if (item.signedBy && item.expectedSha256) {
      const sig = await verifyAuthenticode(tmp, item.signedBy, codesignOptions(e));
      if (sig.ok) {
        verification = "VERIFIED";
        reason = null;
      } else {
        reason = `digest matched GitHub; not code-signed (${sig.reason}) — requires admin approval`;
      }
    }

    // Record + audit FIRST, then place the file. A file is never served without a DB record.
    const rec = await prisma.$transaction(async (tx) => {
      const r = await tx.mirroredRelease.create({
        data: {
          component: item.component,
          version: item.version,
          assetName: item.assetName,
          sourceUrl: item.url,
          sha256: dl.sha256,
          sizeBytes: BigInt(dl.size),
          repoPath: rel,
          verification,
          rejectReason: reason,
        },
      });
      await appendAudit(
        {
          actor: "system:fetcher",
          action: `mirror.${verification.toLowerCase()}`,
          entity: "MirroredRelease",
          entityId: r.id,
          payload: { component: item.component, version: item.version, asset: item.assetName, sha256: dl.sha256, reason },
        },
        tx,
      );
      return r;
    });

    try {
      if (verification === "VERIFIED") await publishFile(e.REPO_DIR, tmp, rel);
      else if (verification === "PENDING") {
        const dest = pendingAbs(e.REPO_DIR, rel);
        await mkdir(dirname(dest), { recursive: true });
        await rename(tmp, dest);
      }
    } catch (err: unknown) {
      const msg = `file placement failed: ${err instanceof Error ? err.message : "unknown"}`;
      await prisma.mirroredRelease.update({ where: { id: rec.id }, data: { verification: "REJECTED", rejectReason: msg } });
      await appendAudit({ actor: "system:fetcher", action: "mirror.rejected", entity: "MirroredRelease", entityId: rec.id, payload: { reason: msg } });
      return "rejected";
    }
    if (verification === "VERIFIED" && item.component === "TACTICAL_AGENT") await ensureAgentUpgradePatch(item.version);
    return verification.toLowerCase();
  } finally {
    await discardTemp(tmp);
  }
}

export async function mirrorTacticalReleases(): Promise<Record<string, string>> {
  const run = await prisma.fetchRun.create({ data: { source: "tactical" } });
  const out: Record<string, string> = {};
  try {
    const agent = releaseSchema.parse(
      await safeFetchJson("https://api.github.com/repos/amidaware/rmmagent/releases/latest", ghOpts()),
    );
    for (const a of agent.assets) {
      const m = AGENT_ASSET.exec(a.name);
      if (!m) continue;
      const digest = a.digest?.startsWith("sha256:") ? a.digest.slice(7).toLowerCase() : null;
      out[a.name] = await mirrorOne({
        component: "TACTICAL_AGENT",
        version: m[1],
        assetName: a.name,
        url: a.browser_download_url,
        expectedSha256: digest && /^[a-f0-9]{64}$/.test(digest) ? digest : null,
        signedBy: AGENT_PUBLISHER,
      });
    }

    const server = releaseSchema.parse(
      await safeFetchJson("https://api.github.com/repos/amidaware/tacticalrmm/releases/latest", ghOpts()),
    );
    const tm = TAG.exec(server.tag_name);
    if (tm) {
      out[`tacticalrmm-${tm[1]}`] = await mirrorOne({
        component: "TACTICAL_SERVER",
        version: tm[1],
        assetName: `tacticalrmm-${tm[1]}.tar.gz`,
        url: server.tarball_url,
        expectedSha256: null,
        signedBy: null,
      });
    }
    await prisma.fetchRun.update({ where: { id: run.id }, data: { finishedAt: new Date(), ok: true, message: JSON.stringify(out) } });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message.slice(0, 300) : "unknown error";
    await prisma.fetchRun.update({ where: { id: run.id }, data: { finishedAt: new Date(), ok: false, message: msg } });
    throw err;
  }
  return out;
}

/** Admin decision on a PENDING mirror (file moves into the served tree only on approve). */
export async function decideMirror(id: string, approve: boolean, actorUpn: string): Promise<void> {
  const e = env();
  const rec = await prisma.mirroredRelease.findUnique({ where: { id } });
  if (!rec) throw new DomainError("Mirrored release not found", 404);
  if (rec.verification !== "PENDING") throw new DomainError("Only pending releases can be decided", 409);

  const pending = pendingAbs(e.REPO_DIR, rec.repoPath);
  const dest = repoAbsPath(e.REPO_DIR, rec.repoPath);

  // Approve: move the file FIRST (fails cleanly if it is missing), then flip the DB + audit atomically.
  // If the DB step loses a race, the file is moved back so DB and disk never disagree.
  if (approve) {
    await mkdir(dirname(dest), { recursive: true });
    try {
      await rename(pending, dest);
    } catch {
      throw new DomainError("Pending file is missing on disk; re-run the mirror fetch", 409);
    }
  }

  try {
    await prisma.$transaction(async (tx) => {
      const { count } = await tx.mirroredRelease.updateMany({
        where: { id, verification: "PENDING" },
        data: approve
          ? { verification: "VERIFIED", rejectReason: null }
          : { verification: "REJECTED", rejectReason: `rejected by ${actorUpn}` },
      });
      if (count !== 1) throw new DomainError("Release was modified concurrently", 409);
      await appendAudit(
        {
          actor: actorUpn,
          action: approve ? "mirror.approve" : "mirror.reject",
          entity: "MirroredRelease",
          entityId: id,
          payload: { component: rec.component, version: rec.version, sha256: rec.sha256 },
        },
        tx,
      );
    });
  } catch (err: unknown) {
    if (approve) await rename(dest, pending).catch(() => undefined);
    throw err;
  }

  if (!approve) await discardTemp(pending);
  else if (rec.component === "TACTICAL_AGENT") await ensureAgentUpgradePatch(rec.version);
}

const DAILY_MS = 24 * 60 * 60_000;

export async function mirrorTacticalDue(now = new Date()) {
  const last = await prisma.fetchRun.findFirst({ where: { source: "tactical" }, orderBy: { startedAt: "desc" } });
  if (last && now.getTime() - last.startedAt.getTime() < DAILY_MS) return { skipped: true };
  return mirrorTacticalReleases();
}

/**
 * Once an agent build is approved (VERIFIED), expose it as a selectable AGENT_UPGRADE patch
 * that goes through the normal change-request flow. Older agent patches are superseded.
 */
const AGENT_PATCH_LOCK = 4_242_002;

export async function ensureAgentUpgradePatch(version: string): Promise<void> {
  // Only offer the upgrade once EVERY Windows architecture has an approved build.
  const builds = await prisma.mirroredRelease.findMany({
    where: { component: "TACTICAL_AGENT", version, verification: "VERIFIED" },
    select: { version: true, sha256: true, repoPath: true, assetName: true },
  });
  if (!hasAllAgentArches(builds)) return;

  await prisma.$transaction(async (tx) => {
    // Serialise so concurrent approvals can never leave two "latest" agent patches.
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(${AGENT_PATCH_LOCK})`;
    await tx.patch.upsert({
      where: { externalId: `tactical-agent@${version}` },
      create: {
        kind: "AGENT_UPGRADE",
        externalId: `tactical-agent@${version}`,
        title: `Tactical RMM agent ${version}`,
        classification: "Management agent",
        severity: "IMPORTANT",
        releasedAt: new Date(),
        agentVersion: version,
      },
      update: {},
      select: { id: true },
    });
    const live = await tx.patch.findMany({
      where: { kind: "AGENT_UPGRADE", supersededById: null, agentVersion: { not: null } },
      select: { id: true, agentVersion: true },
    });
    // The newest live version wins; every other live agent patch is superseded by it
    // (covers approving an OLDER build after a newer one exists).
    const newest = live.reduce((best, p) => (compareVersions(p.agentVersion!, best.agentVersion!) > 0 ? p : best));
    const others = live.filter((p) => p.id !== newest.id).map((p) => p.id);
    if (others.length > 0) {
      await tx.patch.updateMany({ where: { id: { in: others } }, data: { supersededById: newest.id } });
    }
  });
}
