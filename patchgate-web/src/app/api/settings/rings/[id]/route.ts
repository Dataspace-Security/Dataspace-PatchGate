import { ok } from "@/lib/api/response";
import { deleteRing, updateRing } from "@/lib/policies/rings";
import { bankSettingsRoute, jsonBody } from "@/lib/policies/settings-route";

/** Rename / WSUS group / reboot override of one ring of the active bank (another bank's ring is a 404). */
export async function PATCH(req: Request, ctx: RouteContext<"/api/settings/rings/[id]">): Promise<Response> {
  return bankSettingsRoute(req, async ({ user, tenantId }) => ok(await updateRing(user, tenantId, (await ctx.params).id, await jsonBody(req))));
}

/** Delete an empty ring (no endpoints, no change requests). */
export async function DELETE(req: Request, ctx: RouteContext<"/api/settings/rings/[id]">): Promise<Response> {
  return bankSettingsRoute(req, async ({ user, tenantId }) => ok(await deleteRing(user, tenantId, (await ctx.params).id)));
}
