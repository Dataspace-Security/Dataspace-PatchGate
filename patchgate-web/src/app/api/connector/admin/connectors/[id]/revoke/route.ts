import { z } from "zod";
import { getCurrentUser, requireSameOrigin, requireWriter } from "@/lib/auth/session";
import { handle, ok } from "@/lib/api/response";
import { revokeConnector } from "@/lib/connector/admin";

const bodySchema = z.object({ reason: z.string().trim().max(500).optional() });

/** Platform admins: revoke a connector — its next request is rejected (403), queued jobs are cancelled. */
export async function POST(req: Request, ctx: RouteContext<"/api/connector/admin/connectors/[id]/revoke">): Promise<Response> {
  return handle(async () => {
    requireSameOrigin(req);
    const { id } = await ctx.params;
    const user = await getCurrentUser();
    requireWriter(user);
    const { reason } = bodySchema.parse(await req.json().catch(() => ({})));
    return ok(await revokeConnector(user, id, reason));
  });
}
