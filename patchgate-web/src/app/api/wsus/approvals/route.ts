import { connection } from "next/server";
import { env } from "@/lib/env";
import { fail, handle, ok } from "@/lib/api/response";
import { tokenMatches } from "@/lib/api/token";
import { wsusDesiredState } from "@/lib/wsus/catalog";

/** Polled by scripts/wsus/Sync-WsusApprovals.ps1: desired approval state per WSUS computer group. */
export async function GET(req: Request): Promise<Response> {
  return handle(async () => {
    await connection();
    if (!tokenMatches(req.headers.get("x-wsus-token"), env().WSUS_TOKEN)) return fail("Unauthorized", 401);
    return ok(await wsusDesiredState());
  });
}
