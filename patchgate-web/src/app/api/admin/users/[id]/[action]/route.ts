import { getCurrentUser, requireSameOrigin, requireWriter } from "@/lib/auth/session";
import { fail, handle, ok } from "@/lib/api/response";
import { userAction, userActionSchema } from "@/lib/auth/admin-service";

/** POST /api/admin/users/:id/reset-password | reset-mfa | unlock */
export async function POST(req: Request, ctx: { params: Promise<{ id: string; action: string }> }): Promise<Response> {
  return handle(async () => {
    const { id, action } = await ctx.params;
    const parsed = userActionSchema.safeParse({ action });
    if (!parsed.success) return fail("Unknown action", 404);
    requireSameOrigin(req);
    const actor = await getCurrentUser();
    requireWriter(actor);
    const res = ok(await userAction(actor, id, parsed.data.action));
    res.headers.set("Cache-Control", "no-store");
    return res;
  });
}
