import { getCurrentUser } from "@/lib/auth/session";
import { handle } from "@/lib/api/response";
import { PRINT_CSP } from "@/lib/reports/html";
import { generatePrintable, periodFromParams, periodParamsOf, resolveReportScope } from "@/lib/reports/service";

/** GET /api/reports/print?period=…&scope=all — printable HTML (save as PDF from the browser). Audited. */
export async function GET(req: Request): Promise<Response> {
  return handle(async () => {
    const user = await getCurrentUser();
    const sp = new URL(req.url).searchParams;
    const period = periodFromParams(periodParamsOf(sp));
    const scope = await resolveReportScope(user, sp.get("scope"));
    const { html, sha256 } = await generatePrintable(user, scope, period);
    return new Response(html, {
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-store",
        "Content-Security-Policy": PRINT_CSP,
        "X-Content-Type-Options": "nosniff",
        "X-Report-SHA256": sha256,
      },
    });
  });
}
