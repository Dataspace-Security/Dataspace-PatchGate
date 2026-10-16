import { z } from "zod";
import { getCurrentUser, requireRole, requireSameOrigin } from "@/lib/auth/session";
import { fail, handle, ok } from "@/lib/api/response";
import { approveAllowlistRequest, declineAllowlistRequest, manageDiscovered, setDiscoveredIgnored } from "@/lib/discovery/service";
import { isPlatformAdmin, requirePlatformAdmin, requireTenant } from "@/lib/tenancy";

const declineSchema = z.object({ reason: z.string().max(500).default("") });

/**
 * Admin actions on a discovered product.
 * - manage / ignore / unignore: for the active bank. "manage" opts the bank in to an app already on the
 *   shared allow-list; for a NEW app only a platform admin adds it — a bank admin's click files a request.
 * - approve / decline: PatchGate platform admins decide a bank's allow-list request (any bank).
 */
export async function POST(req: Request, ctx: RouteContext<"/api/discovery/[id]/[action]">): Promise<Response> {
  return handle(async () => {
    requireSameOrigin(req);
    const user = await getCurrentUser();
    requireRole(user, ["ADMIN"]);
    const { id, action } = await ctx.params;
    if (action === "approve" || action === "decline") {
      requirePlatformAdmin(user);
      if (action === "approve") return ok(await approveAllowlistRequest(id, user.upn));
      const body = declineSchema.parse(await req.json().catch(() => ({})));
      await declineAllowlistRequest(id, user.upn, body.reason);
      return ok({ id, action });
    }
    const tenantId = await requireTenant(user);
    if (action === "manage") return ok(await manageDiscovered(tenantId, id, { upn: user.upn, platformAdmin: isPlatformAdmin(user) }));
    if (action === "ignore" || action === "unignore") {
      await setDiscoveredIgnored(tenantId, id, action === "ignore", user.upn);
      return ok({ id, action });
    }
    return fail("Unknown action", 404);
  });
}
