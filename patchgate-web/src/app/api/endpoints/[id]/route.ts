import { z } from "zod";
import { getCurrentUser, requireRole, requireSameOrigin } from "@/lib/auth/session";
import { handle, ok } from "@/lib/api/response";
import { appendAudit } from "@/lib/audit/service";
import { DomainError } from "@/lib/errors";
import { requireTenant, withTenant } from "@/lib/tenancy";

const bodySchema = z.object({ ringId: z.string().min(1).nullable() });

/** Assign an endpoint of the active bank to one of that bank's rollout rings (or unassign with null). */
export async function PATCH(req: Request, ctx: RouteContext<"/api/endpoints/[id]">): Promise<Response> {
  return handle(async () => {
    requireSameOrigin(req);
    const user = await getCurrentUser();
    requireRole(user, ["OPERATOR", "APPROVER", "ADMIN"]);
    const tenantId = await requireTenant(user);
    const { id } = await ctx.params;
    const { ringId } = bodySchema.parse(await req.json());

    await withTenant(tenantId, async (tx) => {
      const ep = await tx.endpoint.findFirst({ where: { id, tenantId }, select: { ringId: true, hostname: true } });
      if (!ep) throw new DomainError("Endpoint not found", 404);
      if (ringId && !(await tx.ring.findFirst({ where: { id: ringId, tenantId }, select: { id: true } }))) {
        throw new DomainError("Ring not found", 404);
      }
      await tx.endpoint.updateMany({ where: { id, tenantId }, data: { ringId } });
      await appendAudit(
        {
          tenantId,
          actor: user.upn,
          action: "endpoint.assign_ring",
          entity: "Endpoint",
          entityId: id,
          payload: { hostname: ep.hostname, from: ep.ringId, to: ringId },
        },
        tx,
      );
    });
    return ok({ id, ringId });
  });
}
