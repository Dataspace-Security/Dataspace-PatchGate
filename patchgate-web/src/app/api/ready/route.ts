import { connection } from "next/server";
import { readiness } from "@/lib/health";

/** Readiness for the load balancer (503 = out of rotation) + integrity signals for monitoring. */
export async function GET(): Promise<Response> {
  await connection();
  const r = await readiness();
  return Response.json(r, { status: r.ready ? 200 : 503, headers: { "Cache-Control": "no-store" } });
}
