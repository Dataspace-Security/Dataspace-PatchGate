import { localAuthRoute } from "@/lib/auth/login-response";
import { changePasswordSchema, changePasswordStep } from "@/lib/auth/local-login";

/** Local sign-in step 3 (temporary password issued by an admin): set a new password → session. */
export async function POST(req: Request): Promise<Response> {
  return localAuthRoute(req, changePasswordSchema, ({ newPassword }, { meta, mfaToken }) => changePasswordStep(mfaToken, newPassword, meta));
}
