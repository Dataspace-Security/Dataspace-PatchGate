import { getCurrentUser, requireSameOrigin, requireWriter } from "@/lib/auth/session";
import { handle, ok } from "@/lib/api/response";
import { retryNotification } from "@/lib/notify/settings";

/** POST /api/notifications/:id/retry — platform admins; DEAD / SKIPPED rows only (audited). */
export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }): Promise<Response> {
  return handle(async () => {
    requireSameOrigin(req);
    const { id } = await ctx.params;
    const user = await getCurrentUser();
    requireWriter(user);
    return ok(await retryNotification(user, id));
  });
}
