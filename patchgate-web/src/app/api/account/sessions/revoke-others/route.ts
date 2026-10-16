import { accountRoute } from "@/lib/auth/account-route";
import { revokeOtherSessions } from "@/lib/auth/account-service";

/** Sign out of all other sessions (keeps this one), audited. */
export async function POST(req: Request): Promise<Response> {
  return accountRoute(req, null, (ctx, _input, meta) => revokeOtherSessions(ctx, meta));
}
