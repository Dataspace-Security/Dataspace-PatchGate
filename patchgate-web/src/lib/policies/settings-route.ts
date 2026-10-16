import "server-only";
import { handle } from "@/lib/api/response";
import { getCurrentUser, requireSameOrigin, type SessionUser } from "@/lib/auth/session";
import { requireSettingsAdmin } from "./settings-access";

/**
 * Route skeleton for /api/settings/** (bank settings): same-origin for mutations, signed in, ADMIN acting for
 * the active bank (bank admin: own bank; platform admin: selected bank). Errors map to the JSON envelope.
 */
export function bankSettingsRoute(
  req: Request,
  run: (ctx: { user: SessionUser; tenantId: string }) => Promise<Response>,
): Promise<Response> {
  return handle(async () => {
    if (req.method !== "GET" && req.method !== "HEAD") requireSameOrigin(req);
    const user = await getCurrentUser();
    const tenantId = await requireSettingsAdmin(user);
    return run({ user, tenantId });
  });
}

/** Read the JSON body (null when absent / malformed: the zod schema then reports it). */
export async function jsonBody(req: Request): Promise<unknown> {
  return req.json().catch(() => null);
}
