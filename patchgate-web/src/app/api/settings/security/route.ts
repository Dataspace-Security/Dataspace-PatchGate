import { AuthError, getCurrentUser, requireSameOrigin, requireWriter } from "@/lib/auth/session";
import { isPlatformReader } from "@/lib/tenancy/policy";
import { handle, ok } from "@/lib/api/response";
import { jsonBody } from "@/lib/policies/settings-route";
import { securityPolicyView, updateSecurityPolicy } from "@/lib/policies/security-store";
import { requirePlatformAdmin } from "@/lib/tenancy";

/** Platform account security policy (platform admins change it; platform auditors read it). Session timeouts are read-only (env). */
export async function GET(): Promise<Response> {
  return handle(async () => {
    if (!isPlatformReader(await getCurrentUser())) throw new AuthError("Platform staff only", 403);
    return ok(await securityPolicyView());
  });
}

export async function PATCH(req: Request): Promise<Response> {
  return handle(async () => {
    requireSameOrigin(req);
    const user = await getCurrentUser();
    requireWriter(user);
    requirePlatformAdmin(user);
    return ok(await updateSecurityPolicy(user, await jsonBody(req)));
  });
}
