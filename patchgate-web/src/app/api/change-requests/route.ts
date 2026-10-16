import { getCurrentUser, requireSameOrigin, requireWriter } from "@/lib/auth/session";
import { handle, ok } from "@/lib/api/response";
import { createChangeRequest, createChangeRequestSchema } from "@/lib/approvals/service";
import { requireTenant, withTenant } from "@/lib/tenancy";

/** Change requests of the active bank only. */
export async function GET(): Promise<Response> {
  return handle(async () => {
    const user = await getCurrentUser();
    const tenantId = await requireTenant(user);
    const items = await withTenant(tenantId, (tx) =>
      tx.changeRequest.findMany({
        where: { tenantId },
        orderBy: { createdAt: "desc" },
        take: 100,
        include: {
          ring: { select: { name: true } },
          createdBy: { select: { name: true } },
          approvedBy: { select: { name: true } },
          _count: { select: { patches: true, deployments: true } },
        },
      }),
    );
    return ok(items);
  });
}

export async function POST(req: Request): Promise<Response> {
  return handle(async () => {
    requireSameOrigin(req);
    const user = await getCurrentUser();
    requireWriter(user);
    const tenantId = await requireTenant(user);
    const input = createChangeRequestSchema.parse(await req.json());
    return ok(await createChangeRequest(user, tenantId, input), 201);
  });
}
