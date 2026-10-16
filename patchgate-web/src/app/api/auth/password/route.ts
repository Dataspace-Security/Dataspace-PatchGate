import { localAuthRoute } from "@/lib/auth/login-response";
import { beginPasswordLogin, passwordLoginSchema } from "@/lib/auth/local-login";

/** Local sign-in step 1 (password only): username + password → session, or the forced password change. */
export async function POST(req: Request): Promise<Response> {
  return localAuthRoute(req, passwordLoginSchema, (input, { meta }) => beginPasswordLogin(input, meta));
}
