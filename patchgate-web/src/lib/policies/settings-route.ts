import "server-only";
import { handle } from "@/lib/api/response";
import { getCurrentUser, requireSameOrigin, type SessionUser } from "@/lib/auth/session";
import { requireSettingsAdmin, requireSettingsReader } from "./settings-access";

/**
 * Route skeleton for /api/settings/** (bank settings): same-origin for mutations, signed in, acting for the
 * active bank (bank user: own bank; platform staff: selected bank). Reads (GET/HEAD): ADMIN or AUDITOR;
 * every other method: ADMIN only. Errors map to the JSON envelope.
 */
export function bankSettingsRoute(
  req: Request,
  run: (ctx: { user: SessionUser; tenantId: string }) => Promise<Response>,
): Promise<Response> {
  return handle(async () => {
    const read = req.method === "GET" || req.method === "HEAD";
    if (!read) requireSameOrigin(req);
    const user = await getCurrentUser();
    const tenantId = read ? await requireSettingsReader(user) : await requireSettingsAdmin(user);
    return run({ user, tenantId });
  });
}

/** Read the JSON body (null when absent / malformed: the zod schema then reports it). */
export async function jsonBody(req: Request): Promise<unknown> {
  return req.json().catch(() => null);
}
