import { getCurrentUser, requireSameOrigin, requireWriter } from "@/lib/auth/session";
import { handle, ok } from "@/lib/api/response";
import { updateDraftOptions } from "@/lib/approvals/emergency";
import { requireTenant } from "@/lib/tenancy";

/** Maker's draft options: emergency flag (+ reason) and reboot policy. Draft + creator only (service). */
export async function PATCH(req: Request, ctx: RouteContext<"/api/change-requests/[id]/options">): Promise<Response> {
  return handle(async () => {
    requireSameOrigin(req);
    const user = await getCurrentUser();
    requireWriter(user);
    const tenantId = await requireTenant(user);
    const { id } = await ctx.params;
    return ok(await updateDraftOptions(user, tenantId, id, await req.json().catch(() => null)));
  });
}
