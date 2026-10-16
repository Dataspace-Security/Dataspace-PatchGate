import { connection } from "next/server";
import { bundleFileResponse } from "@/lib/connector/bundle-http";

/**
 * GET /install/bundle/<version|latest>/<SHA256SUMS | SHA256SUMS.sig | file listed in SHA256SUMS>
 * Header `Authorization: PatchGate-Enrolment <code>` (unused, unexpired code of an active bank; not consumed).
 * Archives are streamed from the read-only bundle volume with Range/206 support (resume).
 */
export async function GET(req: Request, ctx: RouteContext<"/install/bundle/[version]/[file]">): Promise<Response> {
  await connection();
  const { version, file } = await ctx.params;
  return bundleFileResponse(req, version, file);
}
