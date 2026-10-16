import "server-only";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { mkdir, rename } from "node:fs/promises";
import { dirname } from "node:path";
import type { App, AppVersion, Prisma } from "@prisma/client";
import { prisma } from "@/lib/db";
import { env } from "@/lib/env";
import { appendAudit } from "@/lib/audit/service";
import { enqueueNotification } from "@/lib/notify/enqueue";
import { DomainError } from "@/lib/errors";
import { packageInputSchema } from "@/lib/thirdparty/package-input";
import { decideTrust } from "@/lib/thirdparty/trust";
import { compareVersions } from "@/lib/thirdparty/version";
import { appendPin } from "./dn";
import { assertAllowedUrl, assertPublicHttpsUrl, safeDownload, safeFetchJson, safeFetchText } from "./http";
import { discardTemp, newTempFile, pendingAbs, publishFile, repoAbsPath } from "./repo";
import { readAuthenticode, readFileVersion } from "./signature";
import {
  WINGET_HOSTS,
  contentsListingSchema,
  installerManifestUrl,
  pickLatestVersion,
  repoSegment,
  selectInstaller,
  versionsApiUrl,
} from "./winget";

/**
 * Third-party fetch pipeline (the only place third-party bytes enter the bank):
 *   winget manifest → https download (first hop: app allow-list, else the manifest's vendor host;
 *   redirects: strict allow-list or any PUBLIC https host) → SHA-256 + Authenticode → decideTrust:
 *   publish (served, quarantined) | hold in .pending for an admin trust decision | reject.
 */

export type FetchAppResult =
  | { status: "up-to-date"; version: string }
  | { status: "published"; version: string; availableAt: Date }
  | { status: "held"; version: string; reason: string }
  | { status: "rejected"; version: string | null; reason: string };

function ghAuth(): { host: string; headers: Record<string, string> } | undefined {
  const token = env().GITHUB_TOKEN;
  return token ? { host: "api.github.com", headers: { Authorization: `Bearer ${token}` } } : undefined;
}

/** Hosts allowed for the FIRST download hop: the app's explicit list, else the manifest URL's host. */
export function firstHopHosts(app: Pick<App, "allowedDomains">, installerUrl: string): string[] {
  if (app.allowedDomains.length > 0) return app.allowedDomains;
  return [assertPublicHttpsUrl(installerUrl).hostname.toLowerCase()];
}

/**
 * Create the THIRD_PARTY patch for a newly VERIFIED version. Supersedes OLDER versions only; if a newer
 * version is already published (late approval of an old hold), the new patch is itself superseded.
 */
async function createPatchFor(tx: Prisma.TransactionClient, app: App, v: AppVersion, now: Date): Promise<void> {
  const patch = await tx.patch.create({
    data: {
      kind: "THIRD_PARTY",
      externalId: `${app.wingetId}@${v.version}`,
      title: `${app.displayName} ${v.version}`,
      classification: "Third-party application",
      severity: "UNSPECIFIED",
      releasedAt: now,
      appVersionId: v.id,
    },
  });
  const others = await tx.patch.findMany({
    where: { kind: "THIRD_PARTY", appVersion: { appId: app.id }, id: { not: patch.id }, supersededById: null },
    include: { appVersion: true },
  });
  const older = others.filter((o) => o.appVersion && compareVersions(o.appVersion.version, v.version) < 0);
  const newer = others.filter((o) => o.appVersion && compareVersions(o.appVersion.version, v.version) > 0);
  if (older.length > 0) {
    await tx.patch.updateMany({ where: { id: { in: older.map((o) => o.id) } }, data: { supersededById: patch.id } });
  }
  if (newer.length > 0) {
    const newest = newer.reduce((a, b) => (compareVersions(a.appVersion!.version, b.appVersion!.version) >= 0 ? a : b));
    await tx.patch.update({ where: { id: patch.id }, data: { supersededById: newest.id } });
  }
}

/** Fetch the latest installer for one allow-listed app into the internal repo (quarantined or held). */
export async function fetchApp(app: App, now = new Date()): Promise<FetchAppResult> {
  const e = env();
  const run = await prisma.fetchRun.create({ data: { source: `winget:${app.wingetId}` } });
  let version: string | null = null;

  const finish = async (result: FetchAppResult) => {
    await prisma.fetchRun.update({
      where: { id: run.id },
      data: {
        finishedAt: new Date(),
        ok: result.status !== "rejected",
        message: "reason" in result ? `${result.status}: ${result.reason}` : `${result.status} ${result.version}`,
      },
    });
    if (result.status !== "up-to-date") {
      await appendAudit({
        actor: "system:fetcher",
        action: `package.${result.status}`,
        entity: "App",
        entityId: app.id,
        payload: { wingetId: app.wingetId, version: result.version, reason: "reason" in result ? result.reason : null },
      });
    }
    return result;
  };

  /** record=true only for verification failures; transient errors (network) retry next day. */
  const reject = async (reason: string, record = true): Promise<FetchAppResult> => {
    if (version && record) {
      await prisma.appVersion.upsert({
        where: { appId_version: { appId: app.id, version } },
        create: { appId: app.id, version, installerUrl: "-", sha256: "-", silentArgs: "", verification: "REJECTED", rejectReason: reason },
        update: {},
      });
    }
    return finish({ status: "rejected", version, reason });
  };

  try {
    const meta = { allowedHosts: [...WINGET_HOSTS], timeoutMs: 30_000, authHeaders: ghAuth() };
    const listing = contentsListingSchema.parse(await safeFetchJson(versionsApiUrl(app.wingetId), meta));
    version = pickLatestVersion(listing.filter((x) => x.type === "dir").map((x) => x.name));
    if (!version) return reject("no versions found in winget catalog", false);

    const existing = await prisma.appVersion.findUnique({ where: { appId_version: { appId: app.id, version } } });
    if (existing?.verification === "REJECTED") {
      // Already rejected and alerted; a newer upstream version is needed (or an admin re-check).
      await prisma.fetchRun.update({ where: { id: run.id }, data: { finishedAt: new Date(), ok: false, message: `previously rejected ${version}` } });
      return { status: "rejected", version, reason: existing.rejectReason ?? "previously rejected" };
    }
    if (existing?.verification === "HELD") {
      await prisma.fetchRun.update({ where: { id: run.id }, data: { finishedAt: new Date(), ok: true, message: `awaiting decision ${version}` } });
      return { status: "held", version, reason: existing.holdReason ?? "held" };
    }
    if (existing) return finish({ status: "up-to-date", version });

    const installer = selectInstaller(await safeFetchText(installerManifestUrl(app.wingetId, version), meta));
    if (!installer) {
      return reject("no machine-scope MSI, or EXE with an allow-listed silent switch set, in the manifest");
    }

    const hosts = firstHopHosts(app, installer.url);
    assertAllowedUrl(installer.url, hosts);

    const seg = repoSegment(app.wingetId);
    const repoPath = `pkgs/${seg}/${version}/${seg}-${version}.${installer.kind}`;

    const tmp = await newTempFile(e.REPO_DIR);
    try {
      const dl = await safeDownload(installer.url, tmp, {
        allowedHosts: hosts,
        redirects: app.strictHosts ? "allowlist" : "public",
        timeoutMs: e.FETCH_TIMEOUT_MS,
        maxBytes: e.FETCH_MAX_BYTES,
      });
      const signature = await readAuthenticode(tmp, { codesignCaFile: e.CODESIGN_CA_FILE });
      const decision = decideTrust({
        signature,
        pins: app.expectedPublisher,
        catalogSha256: installer.sha256,
        actualSha256: dl.sha256,
        allowHashDrift: app.allowHashDrift,
      });
      if (decision.action === "reject") return reject(decision.reason);

      const pkgCheck = packageInputSchema.safeParse({
        kind: installer.kind,
        wingetId: app.wingetId,
        version,
        sha256: dl.sha256,
        repoPath,
        publisher: `O=${decision.signerOrg}`,
        switches: installer.switches,
      });
      if (!pkgCheck.success) return reject("package metadata failed validation");

      const fileVersion = await readFileVersion(tmp, installer.kind);
      const evidence = {
        appId: app.id,
        version,
        installerUrl: installer.url,
        sha256: dl.sha256,
        catalogSha256: installer.sha256,
        silentArgs: installer.switches,
        installerKind: installer.kind === "exe" ? ("EXE" as const) : ("MSI" as const),
        installerType: installer.installerType,
        signerOrg: decision.signerOrg,
        signerSubject: signature.ok ? signature.subject.slice(0, 1000) : null,
        fileVersion,
        repoPath,
      };

      if (decision.action === "hold") {
        const dest = pendingAbs(e.REPO_DIR, repoPath);
        await mkdir(dirname(dest), { recursive: true });
        await rename(tmp, dest);
        try {
          await prisma.$transaction(async (tx) => {
            const held = await tx.appVersion.create({ data: { ...evidence, verification: "HELD", holdReason: decision.reason } });
            await enqueueNotification(tx, { event: "PACKAGE_HELD", appVersionId: held.id });
          });
        } catch (err: unknown) {
          await discardTemp(dest);
          throw err;
        }
        return finish({ status: "held", version, reason: `${decision.reason}: ${decision.detail}` });
      }

      await publishFile(e.REPO_DIR, tmp, repoPath);
      const availableAt = new Date(now.getTime() + e.QUARANTINE_HOURS * 3_600_000);
      await prisma.$transaction(async (tx) => {
        const v = await tx.appVersion.create({ data: { ...evidence, verification: "VERIFIED", availableAt } });
        await createPatchFor(tx, app, v, now);
      });
      return finish({ status: "published", version, availableAt });
    } finally {
      await discardTemp(tmp);
    }
  } catch (err: unknown) {
    return reject(err instanceof Error ? err.message.slice(0, 300) : "unknown error", false);
  }
}

async function sha256File(path: string): Promise<string> {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk as Buffer);
  return hash.digest("hex");
}

/**
 * Admin trust decision on a HELD package.
 * Approve: re-hash the held file, move it into the served tree, mark VERIFIED (quarantine starts now),
 * pin the signer organisation for FIRST_SIGNER / SIGNER_CHANGED, create the patch, audit — atomically.
 * Reject: mark REJECTED and delete the held file.
 */
export async function decidePackage(id: string, approve: boolean, actorUpn: string, now = new Date()): Promise<void> {
  const e = env();
  const v = await prisma.appVersion.findUnique({ where: { id }, include: { app: true } });
  if (!v) throw new DomainError("Package not found", 404);
  if (v.verification !== "HELD" || !v.repoPath || !v.signerOrg) throw new DomainError("Only held packages can be decided", 409);

  const pending = pendingAbs(e.REPO_DIR, v.repoPath);
  const dest = repoAbsPath(e.REPO_DIR, v.repoPath);

  if (approve) {
    let actual: string;
    try {
      actual = await sha256File(pending);
    } catch {
      throw new DomainError("Held file is missing on disk; reject it and let the next fetch retry", 409);
    }
    if (actual !== v.sha256) throw new DomainError("Held file changed on disk since download — reject it", 409);
    await mkdir(dirname(dest), { recursive: true });
    await rename(pending, dest);
  }

  try {
    await prisma.$transaction(async (tx) => {
      const { count } = await tx.appVersion.updateMany({
        where: { id, verification: "HELD" },
        data: approve
          ? { verification: "VERIFIED", decidedBy: actorUpn, decidedAt: now, availableAt: new Date(now.getTime() + e.QUARANTINE_HOURS * 3_600_000) }
          : { verification: "REJECTED", decidedBy: actorUpn, decidedAt: now, rejectReason: `rejected by ${actorUpn}` },
      });
      if (count !== 1) throw new DomainError("Package was decided concurrently", 409);

      let pins = v.app.expectedPublisher;
      if (approve) {
        if (v.holdReason !== "HASH_DRIFT") {
          const app = await tx.app.findUniqueOrThrow({ where: { id: v.appId } });
          try {
            pins = appendPin(app.expectedPublisher, v.signerOrg!);
          } catch (err: unknown) {
            throw new DomainError(err instanceof Error ? err.message : "Cannot pin signer", 409);
          }
          await tx.app.update({ where: { id: app.id }, data: { expectedPublisher: pins } });
        }
        const fresh = await tx.appVersion.findUniqueOrThrow({ where: { id } });
        const app = await tx.app.findUniqueOrThrow({ where: { id: v.appId } });
        await createPatchFor(tx, app, fresh, now);
      }
      await appendAudit(
        {
          actor: actorUpn,
          action: approve ? "package.approve" : "package.reject",
          entity: "AppVersion",
          entityId: id,
          payload: {
            wingetId: v.app.wingetId,
            version: v.version,
            sha256: v.sha256,
            catalogSha256: v.catalogSha256,
            holdReason: v.holdReason,
            signerOrg: v.signerOrg,
            pins: approve ? pins : v.app.expectedPublisher,
          },
        },
        tx,
      );
    });
  } catch (err: unknown) {
    if (approve) await rename(dest, pending).catch(() => undefined);
    throw err;
  }

  if (!approve) await discardTemp(pending);
}

const DAILY_MS = 24 * 60 * 60_000;

/** Worker step: refresh each allow-listed app at most once a day. */
export async function fetchDueApps(now = new Date()) {
  const apps = await prisma.app.findMany();
  const results: Record<string, string> = {};
  for (const app of apps) {
    const last = await prisma.fetchRun.findFirst({
      where: { source: `winget:${app.wingetId}` },
      orderBy: { startedAt: "desc" },
    });
    if (last && now.getTime() - last.startedAt.getTime() < DAILY_MS) continue;
    const r = await fetchApp(app, now);
    results[app.wingetId] = r.status;
  }
  return results;
}
