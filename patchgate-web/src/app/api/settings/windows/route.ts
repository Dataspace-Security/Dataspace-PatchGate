import { ok } from "@/lib/api/response";
import { createWindow, listWindows } from "@/lib/policies/windows";
import { bankSettingsRoute, jsonBody } from "@/lib/policies/settings-route";

/** Maintenance windows of the active bank. */
export async function GET(req: Request): Promise<Response> {
  return bankSettingsRoute(req, async ({ tenantId }) => ok(await listWindows(tenantId)));
}

export async function POST(req: Request): Promise<Response> {
  return bankSettingsRoute(req, async ({ user, tenantId }) => ok(await createWindow(user, tenantId, await jsonBody(req)), 201));
}
