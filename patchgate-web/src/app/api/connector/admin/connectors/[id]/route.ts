import { getCurrentUser, requireSameOrigin } from "@/lib/auth/session";
import { handle, ok } from "@/lib/api/response";
import { updateConnectorLimits } from "@/lib/connector/admin";

/** Platform admins: set a connector's LAN limits (maxConcurrentInstalls, bandwidthLimitMbps). Audited. */
export async function PATCH(req: Request, ctx: RouteContext<"/api/connector/admin/connectors/[id]">): Promise<Response> {
  return handle(async () => {
    requireSameOrigin(req);
    const { id } = await ctx.params;
    const user = await getCurrentUser();
    const input: unknown = await req.json().catch(() => null);
    return ok(await updateConnectorLimits(user, id, input));
  });
}
