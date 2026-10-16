import { z } from "zod";
import { getCurrentUser, requireSameOrigin, requireWriter } from "@/lib/auth/session";
import { fail, handle, ok } from "@/lib/api/response";
import { applyAction, decisionSchema } from "@/lib/approvals/service";
import { startDeployment } from "@/lib/deploy/start";
import { requireTenant } from "@/lib/tenancy";

const actionSchema = z.enum(["submit", "approve", "reject", "cancel", "deploy"]);

export async function POST(
  req: Request,
  ctx: RouteContext<"/api/change-requests/[id]/[action]">,
): Promise<Response> {
  return handle(async () => {
    const { id, action: rawAction } = await ctx.params;
    const action = actionSchema.safeParse(rawAction);
    if (!action.success) return fail("Unknown action", 404);

    requireSameOrigin(req);
    // Role, maker-checker and the bank's approval policy are enforced by the state machine inside each
    // service; the request is looked up in the active bank only (another bank's id is a 404).
    const user = await getCurrentUser();
    requireWriter(user);
    const tenantId = await requireTenant(user);

    if (action.data === "deploy") return ok(await startDeployment(user, tenantId, id));

    const body = decisionSchema.parse(await req.json().catch(() => ({})));
    return ok(await applyAction(user, tenantId, id, action.data, body.reason, { deployNow: body.deployNow }));
  });
}
