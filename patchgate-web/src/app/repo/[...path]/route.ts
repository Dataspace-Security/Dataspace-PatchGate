import { createReadStream } from "node:fs";
import { stat } from "node:fs/promises";
import { Readable } from "node:stream";
import { connection } from "next/server";
import { env, repoPublic } from "@/lib/env";
import { realRepoFile } from "@/lib/fetch/repo";

/**
 * Read-only internal package repository for the offline zone (PCs, Tactical server).
 * Only verified files exist under the served tree: downloads land in .tmp, unapproved
 * mirrors in .pending — both unreachable because repo paths must start with an alphanumeric.
 * Restrict by source network at the reverse proxy (offline VLANs only).
 *
 * Hosted model: connectors fetch packages through the signed /api/connector packages endpoint, so this
 * unauthenticated tree is OFF unless REPO_PUBLIC=true (default: off in production, on in development/test;
 * lab setups with PCs downloading straight from PatchGate may enable it). Off = 404 for every path.
 */
export async function GET(_req: Request, ctx: RouteContext<"/repo/[...path]">): Promise<Response> {
  await connection();
  if (!repoPublic()) return new Response("Not found", { status: 404 });
  const { path } = await ctx.params;

  try {
    const abs = await realRepoFile(env().REPO_DIR, path.join("/"));
    const s = await stat(abs);
    if (!s.isFile()) return new Response("Not found", { status: 404 });
    const body = Readable.toWeb(createReadStream(abs)) as ReadableStream<Uint8Array>;
    return new Response(body, {
      headers: {
        "Content-Type": "application/octet-stream",
        "Content-Length": String(s.size),
        "Content-Disposition": `attachment; filename="${path[path.length - 1]}"`,
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-store",
      },
    });
  } catch {
    return new Response("Not found", { status: 404 });
  }
}
