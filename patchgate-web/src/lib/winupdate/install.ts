import "server-only";
import type { Prisma, WinUpdate, WinUpdateFile } from "@prisma/client";
import type { z } from "zod";
import { appendAudit } from "@/lib/audit/service";
import { jobPackageSchema, jobPayloadSchemas, type JobPackage, type resultSchemas } from "@/lib/connector/protocol";
import { WU_MAX_FILES_PER_UPDATE } from "./catalog";
import { MICROSOFT_PUBLISHER, normalizeGuid } from "./microsoft";

type Tx = Prisma.TransactionClient;
export type RebootPolicy = "NEVER" | "IF_REQUIRED" | "FORCE";
export type WuInstallResult = z.infer<(typeof resultSchemas)["WU_INSTALL"]>;

export const WU_PACKAGE_ID = "Microsoft.WindowsUpdate";
const MAX_UPDATES = 100;
const MAX_FILES_PER_UPDATE = WU_MAX_FILES_PER_UPDATE;

export interface WuInstallPlan {
  payload: { updates: { updateId: string; kb: string | null; files: JobPackage[] }[]; rebootPolicy: RebootPolicy };
  cacheNeeds: JobPackage[];
}

export type Readiness = { state: "ready"; files: WinUpdateFile[] } | { state: "wait"; reason: string } | { state: "undeliverable"; reason: string };

/** Pure: can this update be installed now from its file set? */
export function updateReadiness(files: readonly WinUpdateFile[], now: Date): Readiness {
  if (files.length === 0) return { state: "undeliverable", reason: "no installable (.msu/.cab) files reported" };
  if (files.some((f) => f.verification === "REJECTED")) return { state: "undeliverable", reason: "a file of this update was rejected" };
  if (files.some((f) => f.verification !== "VERIFIED")) return { state: "wait", reason: "Microsoft files still downloading / being verified" };
  if (files.some((f) => !f.availableAt || f.availableAt > now)) {
    const until = files.reduce<Date | null>((max, f) => (f.availableAt && (!max || f.availableAt > max) ? f.availableAt : max), null);
    return { state: "wait", reason: until ? `files in quarantine until ${until.toISOString().replace("T", " ").slice(0, 16)} UTC` : "files still in quarantine" };
  }
  if (files.length > MAX_FILES_PER_UPDATE) return { state: "undeliverable", reason: "too many files" };
  return { state: "ready", files: [...files].sort((a, b) => a.ordinal - b.ordinal || a.createdAt.getTime() - b.createdAt.getTime()) };
}

/**
 * Pure: readiness of one update, using ONLY its Microsoft Update Catalog binding. An update still waiting
 * for its catalog lookup waits; one Microsoft does not publish installable files for is undeliverable.
 * Legacy PC-reported files (source REPORTED) are never considered.
 */
export function catalogReadiness(u: Pick<WinUpdate, "catalogState" | "resolveError"> & { files: readonly WinUpdateFile[] }, now: Date): Readiness {
  if (u.catalogState === "PENDING") return { state: "wait", reason: "waiting for the Microsoft Update Catalog lookup" };
  if (u.catalogState === "UNRESOLVABLE") return { state: "undeliverable", reason: u.resolveError ?? "not deliverable from the Microsoft Update Catalog" };
  return updateReadiness(u.files.filter((f) => f.source === "CATALOG"), now);
}

export function fileToPackage(f: WinUpdateFile, kb: string | null, revision: number): JobPackage {
  return jobPackageSchema.parse({
    kind: f.kind,
    wingetId: WU_PACKAGE_ID,
    version: kb ?? `r${revision}`,
    sha256: f.sha256,
    size: Number(f.sizeBytes),
    repoPath: f.repoPath,
    publisher: MICROSOFT_PUBLISHER,
    switches: "",
  });
}

/**
 * WU_INSTALL payload for one endpoint + approved WINDOWS patches. Only updates this PC still NEEDS (or
 * FAILED) are included; updates whose files were rejected / never reported are skipped (undeliverable).
 * Returns null when nothing is deliverable, OR when any needed update is still waiting for its files
 * (download / quarantine): the caller retries later instead of deploying a partial set.
 */
export async function planInstall(
  tx: Tx,
  input: { tenantId: string; endpointId: string; patchIds: string[]; rebootPolicy: RebootPolicy },
  now = new Date(),
): Promise<WuInstallPlan | null> {
  const states = await tx.endpointPatchState.findMany({
    where: { tenantId: input.tenantId, endpointId: input.endpointId, patchId: { in: input.patchIds }, status: { in: ["NEEDED", "FAILED"] }, patch: { kind: "WINDOWS" } },
    select: { patch: { select: { externalId: true, kb: true } } },
  });
  const ids = states.flatMap((s) => {
    const g = normalizeGuid(s.patch.externalId);
    return g ? [g] : [];
  });
  if (ids.length === 0) return null;

  const updates = await tx.winUpdate.findMany({ where: { id: { in: ids } }, include: { files: true } });
  const out: WuInstallPlan["payload"]["updates"] = [];
  for (const u of updates.sort((a, b) => a.id.localeCompare(b.id))) {
    const r = catalogReadiness(u, now);
    if (r.state === "wait") return null;
    if (r.state === "undeliverable") continue;
    const kb = u.kb && /^KB\d{4,8}$/.test(u.kb) ? u.kb : null;
    out.push({ updateId: u.id, kb, files: r.files.map((f) => fileToPackage(f, kb, u.revision)) });
    if (out.length >= MAX_UPDATES) break;
  }
  if (out.length === 0) return null;

  const cache = new Map<string, JobPackage>();
  for (const u of out) for (const f of u.files) cache.set(f.repoPath, f);
  return { payload: { updates: out, rebootPolicy: input.rebootPolicy }, cacheNeeds: [...cache.values()] };
}

/** Store a WU_INSTALL result (inside withTenant(ctx.tenantId)): per-update states + the PC's reboot flag. */
export async function recordInstallResult(
  tx: Tx,
  ctx: { tenantId: string; connectorId: string; jobId: string; deploymentId: string | null },
  result: WuInstallResult,
  now = new Date(),
): Promise<void> {
  const job = await tx.connectorJob.findFirst({ where: { id: ctx.jobId, tenantId: ctx.tenantId }, select: { payload: true } });
  const payload = jobPayloadSchemas.WU_INSTALL.safeParse(job?.payload);
  if (!payload.success) throw new Error("WU_INSTALL result for an unknown or invalid job");
  const endpoint = await tx.endpoint.findFirst({ where: { tenantId: ctx.tenantId, tacticalAgentId: payload.data.agentId }, select: { id: true } });
  if (!endpoint) throw new Error("WU_INSTALL result for an unknown endpoint");

  // Only updates that were in the signed job count; anything else in the result is ignored.
  const requested = new Set(payload.data.updates.map((u) => u.updateId.toLowerCase()));
  const pick = (ids: string[]) => [...new Set(ids.map((i) => i.toLowerCase()).filter((i) => requested.has(i)))];
  const installed = pick(result.installed);
  const failed = result.failed.filter((f) => requested.has(f.updateId.toLowerCase()));

  const patches = await tx.patch.findMany({ where: { kind: "WINDOWS", externalId: { in: [...requested] } }, select: { id: true, externalId: true } });
  const patchOf = new Map(patches.map((p) => [p.externalId, p.id]));
  const setState = async (updateId: string, status: "INSTALLED" | "FAILED", lastResult: string) => {
    const patchId = patchOf.get(updateId);
    if (!patchId) return;
    await tx.endpointPatchState.upsert({
      where: { endpointId_patchId: { endpointId: endpoint.id, patchId } },
      create: { tenantId: ctx.tenantId, endpointId: endpoint.id, patchId, status, lastResult },
      update: { status, lastResult },
    });
  };
  for (const id of installed) await setState(id, "INSTALLED", result.rebootRequired ? "installed via PatchGate (restart pending)" : "installed via PatchGate");
  for (const f of failed) {
    if (installed.includes(f.updateId.toLowerCase())) continue;
    await setState(f.updateId.toLowerCase(), "FAILED", f.error.slice(0, 500));
  }
  await tx.endpoint.updateMany({
    where: { id: endpoint.id, tenantId: ctx.tenantId },
    data: result.rebootRequired ? { rebootRequired: true, rebootRequiredAt: now } : { rebootRequired: false, rebootRequiredAt: null },
  });
  await appendAudit(
    {
      tenantId: ctx.tenantId,
      actor: `connector:${ctx.connectorId}`,
      action: "winupdate.install_result",
      entity: ctx.deploymentId ? "Deployment" : "ConnectorJob",
      entityId: ctx.deploymentId ?? ctx.jobId,
      payload: { jobId: ctx.jobId, endpointId: endpoint.id, outcome: result.outcome, installed, failed: failed.map((f) => ({ updateId: f.updateId, error: f.error.slice(0, 300) })), rebootRequired: result.rebootRequired },
    },
    tx,
  );
}
