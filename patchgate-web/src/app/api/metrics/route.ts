import { env } from "@/lib/env";
import { log } from "@/lib/log";
import { opsSnapshot } from "@/lib/metrics/collect";
import { CONTENT_TYPE } from "@/lib/metrics/prom";
import { renderMetrics } from "@/lib/metrics/render";
import { checkMetricsAuth } from "@/lib/metrics/token";

/**
 * Prometheus scrape endpoint (text format 0.0.4). Bearer METRICS_TOKEN (constant-time compare); 404 when
 * METRICS_TOKEN is not configured. Also blocked at the nginx edge except from the internal monitoring
 * networks (allowlists/health.conf). Aggregates only — never per-PC rows, never secrets.
 */
export async function GET(req: Request): Promise<Response> {
  // Reading the request headers makes this handler dynamic (never prerendered at build time).
  const auth = checkMetricsAuth(req.headers.get("authorization"), env().METRICS_TOKEN);
  const headers = { "Cache-Control": "no-store" };
  if (auth === "disabled") return new Response("Not found\n", { status: 404, headers });
  if (auth === "unauthorized") {
    return new Response("Unauthorized\n", { status: 401, headers: { ...headers, "WWW-Authenticate": 'Bearer realm="metrics"' } });
  }
  try {
    const body = renderMetrics(await opsSnapshot());
    return new Response(body, { status: 200, headers: { ...headers, "Content-Type": CONTENT_TYPE } });
  } catch (err: unknown) {
    log.error("metrics.render_failed", { err });
    return new Response("metrics unavailable\n", { status: 500, headers });
  }
}
