import { z } from "zod";
import { ok } from "@/lib/api/response";
import { confirmBulkAssign, previewBulkAssign } from "@/lib/policies/bulk-assign";
import { bankSettingsRoute, jsonBody } from "@/lib/policies/settings-route";

const modeSchema = z.object({ mode: z.enum(["preview", "confirm"]) });

/**
 * Bulk ring assignment: { mode: "preview", filter } → { count, sample };
 * { mode: "confirm", filter, ringId, expectedCount } → moves the previewed endpoints (audited).
 */
export async function POST(req: Request): Promise<Response> {
  return bankSettingsRoute(req, async ({ user, tenantId }) => {
    const body = (await jsonBody(req)) as { filter?: unknown } | null;
    const { mode } = modeSchema.parse(body);
    return mode === "preview" ? ok(await previewBulkAssign(tenantId, body?.filter)) : ok(await confirmBulkAssign(user, tenantId, body));
  });
}
