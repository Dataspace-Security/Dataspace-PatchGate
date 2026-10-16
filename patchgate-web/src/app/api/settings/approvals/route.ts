import { ok } from "@/lib/api/response";
import { getBankPolicy, updateBankPolicy } from "@/lib/policies/bank-settings";
import { bankSettingsRoute, jsonBody } from "@/lib/policies/settings-route";

/** Approval policy + change defaults of the active bank. */
export async function GET(req: Request): Promise<Response> {
  return bankSettingsRoute(req, async ({ tenantId }) => ok(await getBankPolicy(tenantId)));
}

export async function PATCH(req: Request): Promise<Response> {
  return bankSettingsRoute(req, async ({ user, tenantId }) => ok(await updateBankPolicy(user, tenantId, await jsonBody(req))));
}
