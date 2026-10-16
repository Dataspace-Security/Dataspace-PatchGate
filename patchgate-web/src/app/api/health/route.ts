import { connection } from "next/server";

/** Liveness: the process is up and serving (no dependencies). For the load balancer / orchestrator. */
export async function GET(): Promise<Response> {
  await connection();
  return Response.json({ status: "ok" }, { headers: { "Cache-Control": "no-store" } });
}
