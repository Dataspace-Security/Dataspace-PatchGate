import "server-only";
import { stat } from "node:fs/promises";
import type { Prisma } from "@prisma/client";
import { env } from "@/lib/env";
import { realRepoFile } from "@/lib/fetch/repo";
import type { Tx } from "@/lib/tenancy";
import { verifiedAgentReleases } from "@/lib/approvals/load-eligible";
import { packageInputSchema, type PackageInput } from "@/lib/thirdparty/package-input";
import { agentReleaseToPackage, appVersionToPackage, pickAgentRelease, versionPublisher } from "@/lib/thirdparty/package-from-db";
import { normGuid } from "@/lib/tactical/deploy-plan";
import { planWuInstall } from "@/lib/winupdate/hooks";
import { wuInstallStatus } from "@/lib/winupdate/plan-status";
import { jobPackageSchema, type JobPackage, type JobPayload } from "@/lib/connector/protocol";

/**
 * What one endpoint's share of a change request becomes on the connector: an ordered list of install
 * steps, each ONE typed job (a PC never runs two installers at once):
 *   1. Windows updates — WU_INSTALL when the winupdate pipeline has a plan (cached Microsoft files),
 *      otherwise DEPLOY_WINDOWS (legacy WSUS banks: Tactical approves exactly these GUIDs);
 *   2. third-party packages (DEPLOY_PACKAGE), 3. the Tactical agent upgrade last (it restarts the agent).
 * Every package a step needs must be in the site cache first (cacheNeeds → CACHE_PACKAGE).
 */

export const crPlanInclude = {
  window: true,
  patches: { include: { patch: { include: { appVersion: { include: { app: true } } } } } },
} as const;
export type CrForPlan = Prisma.ChangeRequestGetPayload<{ include: typeof crPlanInclude }>;

export interface EndpointForPlan {
  id: string;
  tacticalAgentId: string;
  goarch: string | null;
}

export type PlannedStep =
  | { key: "windows"; type: "DEPLOY_WINDOWS"; payload: JobPayload<"DEPLOY_WINDOWS">; cacheNeeds: JobPackage[] }
  | { key: "windows"; type: "WU_INSTALL"; payload: JobPayload<"WU_INSTALL">; cacheNeeds: JobPackage[] }
  | { key: string; type: "DEPLOY_PACKAGE"; payload: JobPayload<"DEPLOY_PACKAGE">; cacheNeeds: JobPackage[]; confirm: PackageConfirm };

/** How a package install is confirmed later from collected inventory. */
export type PackageConfirm = { by: "inventory"; match: string; version: string } | { by: "agent"; version: string };

const GUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const MAX_GUIDS = 500;

export function rebootPolicyOf(cr: CrForPlan): "NEVER" | "IF_REQUIRED" | "FORCE" {
  // The request's own policy (set from ring / bank defaults) wins; older requests fall back to the window's.
  switch (cr.rebootPolicy ?? cr.window?.rebootPolicy) {
    case "NEVER":
      return "NEVER";
    case "ALWAYS":
      return "FORCE";
    default:
      return "IF_REQUIRED";
  }
}

export const stepKeyOfPackage = (sha256: string): string => `pkg:${sha256}`;

/** Step key of an existing job (to know which steps are done / in flight). */
export function stepKeyOfJob(type: string, payload: Prisma.JsonValue): string | null {
  if (type === "DEPLOY_WINDOWS" || type === "WU_INSTALL") return "windows";
  if (type === "DEPLOY_PACKAGE") {
    const sha = (payload as { package?: { sha256?: unknown } } | null)?.package?.sha256;
    return typeof sha === "string" ? stepKeyOfPackage(sha) : null;
  }
  return null;
}

/** File sizes are read from the repository once per planning run. */
export class PackageSizer {
  private readonly sizes = new Map<string, number>();

  async toJobPackage(pkg: PackageInput): Promise<JobPackage> {
    const p = packageInputSchema.parse(pkg); // same allow-list as the direct Tactical path
    let size = this.sizes.get(p.repoPath);
    if (size === undefined) {
      let s;
      try {
        s = await stat(await realRepoFile(env().REPO_DIR, p.repoPath));
      } catch {
        throw new Error(`${p.wingetId} ${p.version}: package file is missing from the repository (${p.repoPath})`);
      }
      if (!s.isFile() || s.size <= 0) throw new Error(`${p.wingetId} ${p.version}: package file is empty or not a file`);
      size = s.size;
      this.sizes.set(p.repoPath, size);
    }
    return jobPackageSchema.parse({ ...p, size });
  }
}

function windowsPatchesOf(cr: CrForPlan): { guids: string[]; patchIds: string[] } {
  const win = cr.patches.filter((p) => p.patch.kind === "WINDOWS");
  const guids = [...new Set(win.map((p) => normGuid(p.patch.externalId)).filter((g) => GUID_RE.test(g)))];
  return { guids, patchIds: win.map((p) => p.patch.id) };
}

/**
 * Windows updates for a PatchGate-sourced bank are not deliverable YET (Microsoft files still downloading,
 * being verified or in quarantine). Not a failure: the deployment stays queued and is planned again later.
 */
export class WindowsUpdatesNotReadyError extends Error {
  /** Why it waits, in plain words (stored as the deployment's note, shown in the Note column). */
  readonly reason: string;
  constructor(reason = "Windows update files are not verified yet") {
    super(`${reason} — waiting`);
    this.name = "WindowsUpdatesNotReadyError";
    this.reason = reason;
  }
}

/**
 * Ordered install steps for one endpoint. Throws when the change request cannot be delivered to it.
 * `done` = step keys that already succeeded on this PC: they are not planned again (a Windows step that
 * already ran must never block on "nothing left to install").
 */
export async function planEndpointSteps(
  tx: Tx,
  tenantId: string,
  cr: CrForPlan,
  ep: EndpointForPlan,
  sizer: PackageSizer,
  done: ReadonlySet<string> = new Set(),
): Promise<PlannedStep[]> {
  const steps: PlannedStep[] = [];
  const rebootPolicy = rebootPolicyOf(cr);

  const win = windowsPatchesOf(cr);
  if (win.patchIds.length > 0 && !done.has("windows")) {
    const source = (await tx.tenant.findUnique({ where: { id: tenantId }, select: { windowsUpdateSource: true } }))?.windowsUpdateSource ?? "PATCHGATE";
    if (source === "PATCHGATE") {
      // No WSUS and no internet on these PCs: only WU_INSTALL (cached Microsoft files) can work.
      const status = await wuInstallStatus(tx, { tenantId, endpointId: ep.id, patchIds: win.patchIds });
      if (status.state === "wait") throw new WindowsUpdatesNotReadyError(status.reason);
      if (status.state === "undeliverable") throw new Error(status.reason);
      if (status.state === "ready") {
        const wu = await planWuInstall(tx, { tenantId, endpointId: ep.id, patchIds: win.patchIds, rebootPolicy });
        if (!wu) throw new WindowsUpdatesNotReadyError();
        steps.push(wuStep(ep, wu));
      }
      // "nothing-needed": no Windows step on this PC.
    } else {
      const wu = await planWuInstall(tx, { tenantId, endpointId: ep.id, patchIds: win.patchIds, rebootPolicy });
      if (wu) steps.push(wuStep(ep, wu));
      else if (win.guids.length > 0) {
        if (win.guids.length > MAX_GUIDS) throw new Error(`too many Windows updates in one change request (${win.guids.length} > ${MAX_GUIDS})`);
        steps.push({ key: "windows", type: "DEPLOY_WINDOWS", payload: { agentId: ep.tacticalAgentId, guids: win.guids, rebootPolicy }, cacheNeeds: [] });
      }
    }
  }

  const agentVersions = cr.patches.flatMap(({ patch }) => (patch.kind === "AGENT_UPGRADE" && patch.agentVersion ? [patch.agentVersion] : []));
  const releases = await verifiedAgentReleases(agentVersions, tx);
  const thirdParty: PlannedStep[] = [];
  const agent: PlannedStep[] = [];
  for (const { patch } of cr.patches) {
    if (patch.kind === "THIRD_PARTY") {
      const v = patch.appVersion;
      if (!v || !v.repoPath) throw new Error(`${patch.title}: package is not published in the repository`);
      const pkg = await sizer.toJobPackage(appVersionToPackage({ ...v, wingetId: v.app.wingetId, publisher: versionPublisher(v, v.app.expectedPublisher) }));
      thirdParty.push({
        key: stepKeyOfPackage(pkg.sha256),
        type: "DEPLOY_PACKAGE",
        payload: { agentId: ep.tacticalAgentId, package: pkg },
        cacheNeeds: [pkg],
        confirm: { by: "inventory", match: v.app.inventoryMatch, version: v.version },
      });
    } else if (patch.kind === "AGENT_UPGRADE" && patch.agentVersion) {
      const rel = pickAgentRelease(releases.get(patch.agentVersion) ?? [], ep.goarch);
      if (!rel) throw new Error(`no approved agent ${patch.agentVersion} build for arch ${ep.goarch ?? "unknown"}`);
      const pkg = await sizer.toJobPackage(agentReleaseToPackage(rel));
      agent.push({
        key: stepKeyOfPackage(pkg.sha256),
        type: "DEPLOY_PACKAGE",
        payload: { agentId: ep.tacticalAgentId, package: pkg },
        cacheNeeds: [pkg],
        confirm: { by: "agent", version: patch.agentVersion },
      });
    }
  }
  return [...steps, ...thirdParty, ...agent].filter((s) => !done.has(s.key));
}

type WuPlan = NonNullable<Awaited<ReturnType<typeof planWuInstall>>>;

function wuStep(ep: EndpointForPlan, wu: WuPlan): PlannedStep {
  const files = wu.payload.updates.flatMap((u) => u.files);
  const needs = [...new Map([...wu.cacheNeeds, ...files].map((f) => [f.sha256, f])).values()];
  return { key: "windows", type: "WU_INSTALL", payload: { agentId: ep.tacticalAgentId, updates: wu.payload.updates, rebootPolicy: wu.payload.rebootPolicy }, cacheNeeds: needs };
}
