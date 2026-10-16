import { getCurrentUser, requireRole, requireSameOrigin } from "@/lib/auth/session";
import { fail, handle, ok } from "@/lib/api/response";
import { setTenantAppEnabled } from "@/lib/thirdparty/tenant-apps";
import { requireTenant } from "@/lib/tenancy";

/** Admin: enable / disable a shared allow-listed app for the active bank (TenantApp opt-in). */
// Explicit params type: the generated RouteContext for new routes only exists after `next typegen`.
export async function POST(req: Request, ctx: { params: Promise<{ id: string; action: string }> }): Promise<Response> {
  return handle(async () => {
    const { id, action } = await ctx.params;
    if (action !== "enable" && action !== "disable") return fail("Unknown action", 404);
    requireSameOrigin(req);
    const user = await getCurrentUser();
    requireRole(user, ["ADMIN"]);
    const tenantId = await requireTenant(user);
    return ok(await setTenantAppEnabled(tenantId, id, action === "enable", user.upn));
  });
}
