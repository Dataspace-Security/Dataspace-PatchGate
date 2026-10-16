import { getCurrentUser, requireSameOrigin, requireWriter } from "@/lib/auth/session";
import { handle, ok } from "@/lib/api/response";
import { updateTenant, updateTenantSchema } from "@/lib/auth/admin-service";

/** Edit a bank: name, short code, active (deactivation signs its users out), approval policy. */
export async function PATCH(req: Request, ctx: { params: Promise<{ id: string }> }): Promise<Response> {
  return handle(async () => {
    requireSameOrigin(req);
    const actor = await getCurrentUser();
    requireWriter(actor);
    const { id } = await ctx.params;
    const input = updateTenantSchema.parse(await req.json().catch(() => null));
    return ok(await updateTenant(actor, id, input));
  });
}
