import { localAuthRoute } from "@/lib/auth/login-response";
import { totpCodeSchema, verifyTotpStep } from "@/lib/auth/local-login";

/** Local sign-in step 2: 6-digit authenticator code → session (or the forced password change). */
export async function POST(req: Request): Promise<Response> {
  return localAuthRoute(req, totpCodeSchema, ({ code }, { meta, mfaToken }) => verifyTotpStep(mfaToken, code, meta));
}
