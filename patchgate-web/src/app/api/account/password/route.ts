import { changeOwnPasswordSchema } from "@/lib/auth/account-policy";
import { accountRoute } from "@/lib/auth/account-route";
import { changeOwnPassword } from "@/lib/auth/account-service";

/** Self-service password change (local accounts): current password + new password; signs out every other session. */
export async function POST(req: Request): Promise<Response> {
  return accountRoute(req, changeOwnPasswordSchema, (ctx, input, meta) => changeOwnPassword(ctx, input, meta));
}
