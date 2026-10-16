import "server-only";
import { z } from "zod";
import { prisma } from "@/lib/db";
import { appendAudit } from "@/lib/audit/service";
import { DomainError } from "@/lib/errors";
import { mapSeverity } from "@/lib/scan/map";
import { legacyTacticalTenantId } from "@/lib/tactical/from-env";
import { withTenant } from "@/lib/tenancy";

const GUID = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

export const wsusUpdateSchema = z.object({
  updateId: z.string().regex(GUID),
  title: z.string().min(1).max(500),
  kb: z.string().regex(/^\d{4,8}$/).nullish(),
  classification: z.string().max(100).nullish(),
  msrcSeverity: z.string().max(30).nullish(),
  released: z.iso.datetime({ offset: true }).nullish(),
  supersededBy: z.string().regex(GUID).nullish(),
  cves: z.array(z.string().regex(/^CVE-\d{4}-\d{4,7}$/)).max(200).default([]),
});

export const wsusBatchSchema = z.object({ updates: z.array(wsusUpdateSchema).min(1).max(1000) });
export type WsusUpdate = z.infer<typeof wsusUpdateSchema>;

/**
 * Windows catalog pushed by Export-WsusCatalog.ps1 (WSUS UpdateId == WUA/Tactical GUID) with the ONE shared
 * WSUS_TOKEN of the legacy bank's WSUS server. Patch rows are shared by every bank, so this is CREATE-ONLY:
 * an existing row's title / KB / classification / severity is never overwritten (they may come from the
 * Microsoft Update Catalog binding, or from another source other banks rely on); only empty release date /
 * CVE list are filled in. Supersedence is fill-only and never touches updates bound from the Microsoft Update
 * Catalog. The run is attributed to and audited on the legacy bank's chain (the bank whose WSUS server it is).
 */
export async function ingestWsusCatalog(updates: readonly WsusUpdate[]): Promise<{ upserted: number; superseded: number }> {
  const tenantId = legacyTacticalTenantId();
  const bank = await prisma.tenant.findUnique({ where: { id: tenantId }, select: { active: true } });
  if (!bank?.active) throw new DomainError("WSUS ingestion is only available for the active legacy bank", 409);

  let created = 0;
  let unchanged = 0;
  let filled = 0;
  for (const u of updates) {
    const externalId = u.updateId.toLowerCase();
    const releasedAt = u.released ? new Date(u.released) : null;
    const existing = await prisma.patch.findUnique({ where: { externalId }, select: { id: true, releasedAt: true, cves: true } });
    if (!existing) {
      const r = await prisma.patch.createMany({
        data: [{ kind: "WINDOWS", externalId, kb: u.kb ? `KB${u.kb}` : null, title: u.title, classification: u.classification ?? null, severity: mapSeverity(u.msrcSeverity), releasedAt, cves: u.cves }],
        skipDuplicates: true,
      });
      created += r.count;
      unchanged += 1 - r.count;
      continue;
    }
    const fill = { ...(existing.releasedAt === null && releasedAt ? { releasedAt } : {}), ...(existing.cves.length === 0 && u.cves.length > 0 ? { cves: u.cves } : {}) };
    if (Object.keys(fill).length > 0) {
      await prisma.patch.update({ where: { id: existing.id }, data: fill });
      filled++;
    } else unchanged++;
  }

  // Second pass so the superseding update exists regardless of order within the batch.
  let superseded = 0;
  for (const u of updates) {
    if (!u.supersededBy) continue;
    const externalId = u.updateId.toLowerCase();
    if (await prisma.winUpdate.findFirst({ where: { id: externalId, catalogState: "RESOLVED" }, select: { id: true } })) continue;
    const newer = await prisma.patch.findUnique({ where: { externalId: u.supersededBy.toLowerCase() }, select: { id: true } });
    if (!newer) continue;
    const { count } = await prisma.patch.updateMany({
      where: { externalId, kind: "WINDOWS", supersededById: null },
      data: { supersededById: newer.id },
    });
    superseded += count;
  }

  await appendAudit({
    tenantId,
    actor: "system:wsus",
    action: "wsus.catalog_ingest",
    entity: "Patch",
    entityId: "*",
    payload: { count: updates.length, created, filled, unchanged, superseded },
  });
  return { upserted: created, superseded };
}

export interface WsusDesiredState {
  /** Every ring group PatchGate manages; approvals in these groups not listed below are removed. */
  groups: string[];
  approvals: { updateId: string; wsusGroup: string }[];
}

/**
 * Desired WSUS state for Sync-WsusApprovals.ps1: an update is approved for a ring group ONLY while a
 * change request containing it is DEPLOYING to that ring (i.e. after "deploy", inside the rollout).
 * Approvals for anything else in managed groups are withdrawn, so cancel/reject/complete revokes them.
 * The WSUS server sits next to the direct Tactical link, so it serves the same single (legacy) bank.
 */
export async function wsusDesiredState(tenantId = legacyTacticalTenantId()): Promise<WsusDesiredState> {
  const { rings, rows } = await withTenant(tenantId, async (tx) => ({
    rings: await tx.ring.findMany({ where: { tenantId }, select: { wsusGroup: true } }),
    rows: await tx.changeRequestPatch.findMany({
      where: { patch: { kind: "WINDOWS" }, changeRequest: { tenantId, status: "DEPLOYING" } },
      select: { patch: { select: { externalId: true } }, changeRequest: { select: { ring: { select: { wsusGroup: true } } } } },
    }),
  }));
  const seen = new Set<string>();
  const approvals: { updateId: string; wsusGroup: string }[] = [];
  for (const r of rows) {
    const key = `${r.patch.externalId}|${r.changeRequest.ring.wsusGroup}`;
    if (seen.has(key) || !GUID.test(r.patch.externalId)) continue;
    seen.add(key);
    approvals.push({ updateId: r.patch.externalId, wsusGroup: r.changeRequest.ring.wsusGroup });
  }
  return { groups: rings.map((r) => r.wsusGroup), approvals };
}
