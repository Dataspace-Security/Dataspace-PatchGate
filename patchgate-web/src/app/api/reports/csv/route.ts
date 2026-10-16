import { getCurrentUser } from "@/lib/auth/session";
import { fail, handle } from "@/lib/api/response";
import { isBankSection } from "@/lib/reports/sections";
import { exportAuditLogCsv, exportCsv, periodFromParams, periodParamsOf, resolveReportScope } from "@/lib/reports/service";

/**
 * GET /api/reports/csv?section=…&period=…&scope=all — one report section as CSV (large ones streamed). Audited.
 * section=audit-log: the selected bank's audit chain events of the period (streamed).
 */
export async function GET(req: Request): Promise<Response> {
  return handle(async () => {
    const user = await getCurrentUser();
    const sp = new URL(req.url).searchParams;
    const section = sp.get("section") ?? "summary";
    if (section !== "audit-log" && !isBankSection(section)) return fail("Unknown report section", 400);
    const period = periodFromParams(periodParamsOf(sp));
    const scope = await resolveReportScope(user, sp.get("scope"));
    const { filename, body } = section === "audit-log" ? await exportAuditLogCsv(user, scope, period) : await exportCsv(user, scope, period, section);
    return new Response(body, {
      headers: {
        "Content-Type": "text/csv; charset=utf-8",
        "Content-Disposition": `attachment; filename="${filename}"`,
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
      },
    });
  });
}
