import { getCurrentUser, requireSameOrigin } from "@/lib/auth/session";
import { handle, ok } from "@/lib/api/response";
import { jsonBody } from "@/lib/policies/settings-route";
import { securityPolicyView, updateSecurityPolicy } from "@/lib/policies/security-store";
import { requirePlatformAdmin } from "@/lib/tenancy";

/** Platform account security policy (platform admins only). Session timeouts are read-only (env). */
export async function GET(): Promise<Response> {
  return handle(async () => {
    requirePlatformAdmin(await getCurrentUser());
    return ok(await securityPolicyView());
  });
}

export async function PATCH(req: Request): Promise<Response> {
  return handle(async () => {
    requireSameOrigin(req);
    const user = await getCurrentUser();
    return ok(await updateSecurityPolicy(user, await jsonBody(req)));
  });
}
