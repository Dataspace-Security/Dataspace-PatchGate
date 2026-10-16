import { getCurrentUser, requireRole, requireSameOrigin } from "@/lib/auth/session";
import { fail, handle, ok } from "@/lib/api/response";
import { requirePlatformAdmin } from "@/lib/tenancy";
import { decideMirror } from "@/lib/fetch/tactical";

/** Admin approves/rejects a PENDING Tactical release (e.g. unsigned agent whose digest matched GitHub). */
export async function POST(req: Request, ctx: RouteContext<"/api/mirror/[id]/[decision]">): Promise<Response> {
  return handle(async () => {
    requireSameOrigin(req);
    const user = await getCurrentUser();
    requireRole(user, ["ADMIN"]);
    requirePlatformAdmin(user); // trust decisions on shared packages: our admins only, platform chain
    const { id, decision } = await ctx.params;
    if (decision !== "approve" && decision !== "reject") return fail("Unknown decision", 404);
    await decideMirror(id, decision === "approve", user.upn);
    return ok({ id, decision });
  });
}
