import { getCurrentUser, requireSameOrigin, requireWriter } from "@/lib/auth/session";
import { handle, ok } from "@/lib/api/response";
import { getMyOptOuts, setMyOptOut } from "@/lib/notify/settings";

/** GET: my personal notification switches (non-critical events only). */
export async function GET(): Promise<Response> {
  return handle(async () => ok(await getMyOptOuts(await getCurrentUser())));
}

/** POST { event, optedOut } — audited on the user's chain. */
export async function POST(req: Request): Promise<Response> {
  return handle(async () => {
    requireSameOrigin(req);
    const user = await getCurrentUser();
    requireWriter(user);
    return ok(await setMyOptOut(user, await req.json().catch(() => null)));
  });
}
