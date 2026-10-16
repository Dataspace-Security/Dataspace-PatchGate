import { z } from "zod";
import { getCurrentUser, requireSameOrigin, requireWriter } from "@/lib/auth/session";
import { handle, ok } from "@/lib/api/response";
import { acknowledgeTacticalActivity } from "@/lib/connector/tactical-activity";

const bodySchema = z.object({
  tenantId: z.string().min(1).max(64),
  ids: z.array(z.string().regex(/^[A-Za-z0-9_-]{1,64}$/)).min(1).max(500).optional(),
  reason: z.string().trim().max(500).optional(),
});

/** ADMIN (the bank's, or platform): acknowledge out-of-band Tactical activity of one bank (audited). */
export async function POST(req: Request): Promise<Response> {
  return handle(async () => {
    requireSameOrigin(req);
    const user = await getCurrentUser();
    requireWriter(user);
    const body = bodySchema.parse(await req.json().catch(() => ({})));
    const acknowledged = await acknowledgeTacticalActivity(user, body.tenantId, body.ids ?? null, body.reason || null);
    return ok({ acknowledged, message: `${acknowledged} acknowledged` });
  });
}
