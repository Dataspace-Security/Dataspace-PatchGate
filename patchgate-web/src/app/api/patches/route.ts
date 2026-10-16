import { z } from "zod";
import type { Prisma } from "@prisma/client";
import { getCurrentUser } from "@/lib/auth/session";
import { handle, ok } from "@/lib/api/response";
import { requireTenant, withTenant } from "@/lib/tenancy";

const querySchema = z.object({
  kind: z.enum(["WINDOWS", "THIRD_PARTY"]).optional(),
  severity: z.enum(["CRITICAL", "IMPORTANT", "MODERATE", "LOW", "UNSPECIFIED"]).optional(),
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(200).default(50),
});

/**
 * Shared patch catalog as seen by the active bank: third-party patches only for apps the bank enabled,
 * and "needed" counts from that bank's PCs only.
 */
export async function GET(req: Request): Promise<Response> {
  return handle(async () => {
    const user = await getCurrentUser();
    const tenantId = await requireTenant(user);
    const q = querySchema.parse(Object.fromEntries(new URL(req.url).searchParams));
    const where: Prisma.PatchWhereInput = {
      kind: q.kind,
      severity: q.severity,
      supersededById: null,
      OR: [{ kind: { not: "THIRD_PARTY" } }, { appVersion: { app: { tenants: { some: { tenantId } } } } }],
    };

    const { total, items } = await withTenant(tenantId, async (tx) => ({
      total: await tx.patch.count({ where }),
      items: await tx.patch.findMany({
        where,
        orderBy: [{ severity: "asc" }, { releasedAt: { sort: "desc", nulls: "last" } }],
        skip: (q.page - 1) * q.limit,
        take: q.limit,
        include: { _count: { select: { states: { where: { tenantId, status: "NEEDED" } } } } },
      }),
    }));
    return ok({ items, meta: { total, page: q.page, limit: q.limit } });
  });
}
