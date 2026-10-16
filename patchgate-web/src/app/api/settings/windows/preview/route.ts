import { z } from "zod";
import { fail, ok } from "@/lib/api/response";
import { getBankPolicy } from "@/lib/policies/bank-settings";
import { checkCron, MAX_WINDOW_MIN, MIN_WINDOW_MIN } from "@/lib/policies/cron-preview";
import { bankSettingsRoute, jsonBody } from "@/lib/policies/settings-route";
import { previewWindow } from "@/lib/policies/windows";

const specSchema = z.object({
  cron: z.string().trim().min(1).max(100),
  durationMin: z.coerce.number().int().min(MIN_WINDOW_MIN).max(MAX_WINDOW_MIN),
  timezone: z.string().trim().min(1).max(64),
});

/** Validate a window spec and return its next 5 occurrences in the bank's timezone (no side effects). */
export async function POST(req: Request): Promise<Response> {
  return bankSettingsRoute(req, async ({ tenantId }) => {
    const spec = specSchema.parse(await jsonBody(req));
    const check = checkCron(spec.cron, spec.timezone);
    if (!check.ok) return fail(check.error, 400);
    const { timezone } = await getBankPolicy(tenantId);
    return ok({ bankTimezone: timezone, occurrences: previewWindow(spec, timezone) });
  });
}
