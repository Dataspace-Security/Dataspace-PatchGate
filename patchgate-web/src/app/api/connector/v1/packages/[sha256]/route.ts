import { createReadStream } from "node:fs";
import { Readable } from "node:stream";
import { connection } from "next/server";
import { withConnector } from "@/lib/connector/http";
import { resolvePackageDownload } from "@/lib/connector/packages";
import { BODY_LIMITS } from "@/lib/connector/policy";

/**
 * Package bytes for the site cache (signed GET, empty body). 200 with Content-Length = file size (the
 * size the job declared); 404 when the bank is not entitled or the file is gone (permanent).
 * The connector re-hashes every byte before caching.
 */
export async function GET(req: Request, ctx: RouteContext<"/api/connector/v1/packages/[sha256]">): Promise<Response> {
  await connection();
  const { sha256 } = await ctx.params;
  return withConnector(req, "packages", BODY_LIMITS.get, async ({ connector }) => {
    const file = await resolvePackageDownload(connector, sha256);
    const body = Readable.toWeb(createReadStream(file.path)) as ReadableStream<Uint8Array>;
    return new Response(body, {
      headers: {
        "Content-Type": "application/octet-stream",
        "Content-Length": String(file.size),
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
      },
    });
  });
}
