import { ok } from "@/lib/api/response";
import { reorderRings } from "@/lib/policies/rings";
import { bankSettingsRoute, jsonBody } from "@/lib/policies/settings-route";

/** New rollout order: { ringIds: [...] } listing every ring of the bank once. */
export async function PUT(req: Request): Promise<Response> {
  return bankSettingsRoute(req, async ({ user, tenantId }) => ok(await reorderRings(user, tenantId, await jsonBody(req))));
}
