import { connection } from "next/server";
import { buildInfo } from "@/lib/version";

/**
 * Release identity of this server: { version, buildId, gitSha, protocolVersion }.
 * No dependencies and no secrets (same exposure as /api/health); used by upgrade checks, the smoke test
 * and support to confirm which release is serving before/after a rolling restart.
 */
export async function GET(): Promise<Response> {
  await connection();
  return Response.json(buildInfo(), { headers: { "Cache-Control": "no-store" } });
}
