import { env } from "@/lib/env";
import { fail, handle, ok } from "@/lib/api/response";
import { tokenMatches } from "@/lib/api/token";
import { ingestWsusCatalog, wsusBatchSchema } from "@/lib/wsus/catalog";

/** Called by scripts/wsus/Export-WsusCatalog.ps1 on the PatchGate-zone WSUS server. */
export async function POST(req: Request): Promise<Response> {
  return handle(async () => {
    if (!tokenMatches(req.headers.get("x-wsus-token"), env().WSUS_TOKEN)) return fail("Unauthorized", 401);
    const body = wsusBatchSchema.parse(await req.json());
    return ok(await ingestWsusCatalog(body.updates));
  });
}
