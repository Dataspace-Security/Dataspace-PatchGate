import "server-only";
import type { Prisma } from "@prisma/client";
import { updateReadiness } from "./install";
import { normalizeGuid } from "./microsoft";

/**
 * Why a WU_INSTALL plan is (not) possible for one PC — the deployment pipeline needs to tell apart
 * "nothing to install" (no Windows step at all) from "not deliverable yet" (wait) and "never deliverable"
 * (fail the PC with a reason). planWuInstall (hooks.ts) returns null for all three.
 *
 * Reads the same tables as planInstall (EndpointPatchState, WinUpdate, WinUpdateFile); never writes.
 */
export type WuInstallStatus =
  | { state: "ready" }
  | { state: "nothing-needed" }
  | { state: "wait"; reason: string }
  | { state: "undeliverable"; reason: string };

type Tx = Prisma.TransactionClient;

export async function wuInstallStatus(
  tx: Tx,
  input: { tenantId: string; endpointId: string; patchIds: readonly string[] },
  now = new Date(),
): Promise<WuInstallStatus> {
  if (input.patchIds.length === 0) return { state: "nothing-needed" };
  const states = await tx.endpointPatchState.findMany({
    where: { tenantId: input.tenantId, endpointId: input.endpointId, patchId: { in: [...input.patchIds] }, patch: { kind: "WINDOWS" } },
    select: { status: true, patch: { select: { externalId: true } } },
  });
  const needed = states.filter((s) => s.status === "NEEDED" || s.status === "FAILED");
  if (needed.length === 0) {
    if (states.length > 0) return { state: "nothing-needed" }; // INSTALLED / NOT_APPLICABLE on this PC
    const ep = await tx.endpoint.findFirst({ where: { id: input.endpointId, tenantId: input.tenantId }, select: { lastWuScanAt: true } });
    // Never scanned: we cannot know yet whether the PC needs the updates.
    if (!ep?.lastWuScanAt) return { state: "wait", reason: "the PC has not completed a Windows Update scan yet" };
    return { state: "nothing-needed" }; // scanned, and none of the approved updates was reported as applicable
  }

  const ids = [...new Set(needed.flatMap((s) => normalizeGuid(s.patch.externalId) ?? []))];
  if (ids.length === 0) return { state: "undeliverable", reason: "the approved updates have no valid update id" };
  const updates = await tx.winUpdate.findMany({ where: { id: { in: ids } }, select: { id: true, catalogState: true, files: true } });
  let deliverable = 0;
  const problems: string[] = [];
  for (const id of ids) {
    const u = updates.find((x) => x.id === id);
    if (!u) {
      problems.push(`${id}: not in the update catalog`);
      continue;
    }
    if (u.catalogState === "PENDING") return { state: "wait", reason: "Microsoft Update Catalog lookup still running" };
    if (u.catalogState === "UNRESOLVABLE") {
      problems.push(`${id}: no Microsoft download could be resolved`);
      continue;
    }
    const r = updateReadiness(u.files, now);
    if (r.state === "wait") return { state: "wait", reason: r.reason };
    if (r.state === "undeliverable") problems.push(`${id}: ${r.reason}`);
    else deliverable++;
  }
  if (deliverable > 0) return { state: "ready" };
  return { state: "undeliverable", reason: `no approved Windows update can be delivered: ${problems.slice(0, 5).join("; ")}` };
}
