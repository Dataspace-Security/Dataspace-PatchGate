import { localAuthRoute } from "@/lib/auth/login-response";
import { changePasswordSchema, changePasswordStep } from "@/lib/auth/local-login";

/** Local sign-in step 2 (temporary or expired password): set a new password → session. */
export async function POST(req: Request): Promise<Response> {
  return localAuthRoute(req, changePasswordSchema, ({ newPassword }, { meta, challengeToken }) => changePasswordStep(challengeToken, newPassword, meta));
}
