import { ok } from "@/lib/api/response";
import { createRing, listRings } from "@/lib/policies/rings";
import { bankSettingsRoute, jsonBody } from "@/lib/policies/settings-route";

/** Rollout rings of the active bank (bank admin / platform admin for the selected bank). */
export async function GET(req: Request): Promise<Response> {
  return bankSettingsRoute(req, async ({ tenantId }) => ok(await listRings(tenantId)));
}

export async function POST(req: Request): Promise<Response> {
  return bankSettingsRoute(req, async ({ user, tenantId }) => ok(await createRing(user, tenantId, await jsonBody(req)), 201));
}
