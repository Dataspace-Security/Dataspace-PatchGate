import { ok } from "@/lib/api/response";
import { deleteWindow, updateWindow } from "@/lib/policies/windows";
import { bankSettingsRoute, jsonBody } from "@/lib/policies/settings-route";

/** Replace a maintenance window of the active bank (full body, validated like create). */
export async function PATCH(req: Request, ctx: RouteContext<"/api/settings/windows/[id]">): Promise<Response> {
  return bankSettingsRoute(req, async ({ user, tenantId }) => ok(await updateWindow(user, tenantId, (await ctx.params).id, await jsonBody(req))));
}

export async function DELETE(req: Request, ctx: RouteContext<"/api/settings/windows/[id]">): Promise<Response> {
  return bankSettingsRoute(req, async ({ user, tenantId }) => ok(await deleteWindow(user, tenantId, (await ctx.params).id)));
}
