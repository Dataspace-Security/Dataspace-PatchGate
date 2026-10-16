import { getCurrentUser, requireSameOrigin, requireWriter } from "@/lib/auth/session";
import { fail, handle, ok } from "@/lib/api/response";
import { requirePlatformAdmin } from "@/lib/tenancy";
import { decidePackage } from "@/lib/fetch/thirdparty";

/** Admin trust decision on a HELD third-party package (first signer, signer change, or hash drift). */
export async function POST(req: Request, ctx: RouteContext<"/api/packages/[id]/[decision]">): Promise<Response> {
  return handle(async () => {
    requireSameOrigin(req);
    const user = await getCurrentUser();
    requireWriter(user);
    requirePlatformAdmin(user); // trust decisions on shared packages: our admins only, platform chain
    const { id, decision } = await ctx.params;
    if (decision !== "approve" && decision !== "reject") return fail("Unknown decision", 404);
    await decidePackage(id, decision === "approve", user.upn);
    return ok({ id, decision });
  });
}
