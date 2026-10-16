import "server-only";
import { createHash } from "node:crypto";
import type { Prisma } from "@prisma/client";
import { z } from "zod";
import { appendAudit } from "@/lib/audit/service";
import type { SessionUser } from "@/lib/auth/session";
import { DomainError } from "@/lib/errors";
import { withTenant } from "@/lib/tenancy";
import { globToRegExp } from "./glob";

/**
 * Bulk-assign a bank's endpoints to a ring by site and/or hostname pattern (* and ? wildcards).
 * Two steps: preview (count + sample) → confirm with the previewed count; if the matching set changed
 * in between the confirm is refused, so an admin never moves PCs they did not see counted.
 * Already submitted change requests are unaffected (their targets were snapshotted on submit).
 */

const SAMPLE = 20;
const AUDITED_HOSTNAMES = 200;

export const bulkFilterSchema = z
  .object({
    site: z.string().trim().max(120).optional(),
    hostnamePattern: z
      .string()
      .trim()
      .max(100)
      .regex(/^[A-Za-z0-9*?._-]*$/, "letters, digits, . _ - and the wildcards * ?")
      .optional(),
    /** Only endpoints currently in this ring ("none" = unassigned); omitted = any */
    fromRingId: z.string().min(1).max(64).optional(),
  })
  .refine((f) => !!f.site || !!f.hostnamePattern || !!f.fromRingId, "choose a site, a hostname pattern or a current ring");
export type BulkFilter = z.infer<typeof bulkFilterSchema>;

export const bulkAssignSchema = z.object({
  filter: bulkFilterSchema,
  ringId: z.string().min(1).max(64).nullable(),
  /** The count shown in the preview (required to confirm) */
  expectedCount: z.number().int().min(0),
});

/** The literal text before the first wildcard (narrows the DB query). */
function literalPrefix(glob: string): string {
  const i = glob.search(/[*?]/);
  return i < 0 ? glob : glob.slice(0, i);
}

/** The bank's endpoints matching the filter: DB pre-filter (site, ring, literal prefix), then the full glob. */
async function matchingIds(tx: Prisma.TransactionClient, tenantId: string, f: BulkFilter): Promise<{ id: string; hostname: string; ringId: string | null }[]> {
  const prefix = f.hostnamePattern ? literalPrefix(f.hostnamePattern) : "";
  const where: Prisma.EndpointWhereInput = {
    tenantId,
    ...(f.site ? { site: f.site } : {}),
    ...(f.fromRingId ? { ringId: f.fromRingId === "none" ? null : f.fromRingId } : {}),
    ...(prefix ? { hostname: { startsWith: prefix, mode: "insensitive" } } : {}),
  };
  const rows = await tx.endpoint.findMany({ where, select: { id: true, hostname: true, ringId: true }, orderBy: { hostname: "asc" } });
  if (!f.hostnamePattern) return rows;
  const re = globToRegExp(f.hostnamePattern);
  return rows.filter((r) => re.test(r.hostname));
}

export async function previewBulkAssign(tenantId: string, raw: unknown) {
  const filter = bulkFilterSchema.parse(raw);
  return withTenant(tenantId, async (tx) => {
    const rows = await matchingIds(tx, tenantId, filter);
    return { count: rows.length, sample: rows.slice(0, SAMPLE).map((r) => r.hostname) };
  });
}

export async function confirmBulkAssign(user: SessionUser, tenantId: string, raw: unknown) {
  const input = bulkAssignSchema.parse(raw);
  return withTenant(
    tenantId,
    async (tx) => {
      if (input.ringId && !(await tx.ring.findFirst({ where: { id: input.ringId, tenantId }, select: { id: true } }))) {
        throw new DomainError("Ring not found", 404);
      }
      const rows = await matchingIds(tx, tenantId, input.filter);
      if (rows.length !== input.expectedCount) {
        throw new DomainError(`The selection changed since the preview (${rows.length} endpoints now match, not ${input.expectedCount}); preview again`, 409);
      }
      const ids = rows.filter((r) => r.ringId !== input.ringId).map((r) => r.id);
      let moved = 0;
      for (let i = 0; i < ids.length; i += 5_000) {
        moved += (await tx.endpoint.updateMany({ where: { tenantId, id: { in: ids.slice(i, i + 5_000) } }, data: { ringId: input.ringId } })).count;
      }
      const digest = createHash("sha256").update([...ids].sort().join("\n")).digest("hex");
      await appendAudit(
        {
          tenantId,
          actor: user.upn,
          action: "endpoint.bulk_assign_ring",
          entity: "Ring",
          entityId: input.ringId ?? "none",
          payload: {
            filter: input.filter,
            matched: rows.length,
            moved,
            endpointIdsSha256: digest,
            hostnames: rows.filter((r) => r.ringId !== input.ringId).slice(0, AUDITED_HOSTNAMES).map((r) => r.hostname),
          },
        },
        tx,
      );
      return { matched: rows.length, moved };
    },
    { timeoutMs: 120_000 },
  );
}
