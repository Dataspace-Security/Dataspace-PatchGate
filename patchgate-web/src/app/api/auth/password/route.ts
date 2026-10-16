import { localAuthRoute } from "@/lib/auth/login-response";
import { beginPasswordLogin, passwordLoginSchema } from "@/lib/auth/local-login";

/** Local sign-in step 1: username + password → TOTP challenge (verify or first-time enrolment). */
export async function POST(req: Request): Promise<Response> {
  return localAuthRoute(req, passwordLoginSchema, (input, { meta }) => beginPasswordLogin(input, meta));
}
