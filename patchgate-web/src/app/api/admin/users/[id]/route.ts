import { getCurrentUser, requireSameOrigin, requireWriter } from "@/lib/auth/session";
import { handle, ok } from "@/lib/api/response";
import { requireAccountManager, updateUser, updateUserSchema } from "@/lib/auth/admin-service";

/** Edit name / role, deactivate (kills sessions) or reactivate a user. */
export async function PATCH(req: Request, ctx: { params: Promise<{ id: string }> }): Promise<Response> {
  return handle(async () => {
    requireSameOrigin(req);
    const actor = await getCurrentUser();
    requireWriter(actor);
    requireAccountManager(actor); // bank admins: 403 — accounts are issued by PatchGate only
    const { id } = await ctx.params;
    const input = updateUserSchema.parse(await req.json().catch(() => null));
    return ok(await updateUser(actor, id, input));
  });
}
