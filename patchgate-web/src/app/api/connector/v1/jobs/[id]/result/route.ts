import { after, connection } from "next/server";
import { json, parseJsonBody, withConnector } from "@/lib/connector/http";
import { BODY_LIMITS } from "@/lib/connector/policy";
import { acceptResult, processJobResult } from "@/lib/connector/results";
import { log } from "@/lib/log";

/**
 * Job result: 200 accepted (first result wins) · 409 already accepted · 404 unknown job ·
 * 400/422 invalid. The result is applied right after the response (and by the worker tick if that fails).
 */
export async function POST(req: Request, ctx: RouteContext<"/api/connector/v1/jobs/[id]/result">): Promise<Response> {
  await connection();
  const { id } = await ctx.params;
  return withConnector(req, "result", BODY_LIMITS.result, async ({ connector, body }) => {
    // Registered first: an invalid (422) result is stored as a failure and must be applied too.
    after(async () => {
      try {
        await processJobResult(connector.tenantId, id);
      } catch (err: unknown) {
        log.error("connector.result.after_failed", { jobId: id, err });
      }
    });
    const accepted = await acceptResult(connector, id, parseJsonBody(body));
    return json({ accepted: true, status: accepted.status });
  });
}
