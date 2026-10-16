import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { AuthError, DEV_USER_COOKIE, requireSameOrigin } from "@/lib/auth/session";
import { logout } from "@/lib/auth/oidc";
import { endSession } from "@/lib/auth/session-store";
import { MFA_COOKIE, SESSION_COOKIE } from "@/lib/auth/tokens";
import { authMode, env } from "@/lib/env";
import { describeError } from "@/lib/errors-describe";

/**
 * Sign out (plain HTML form POST — works before/without JavaScript): delete the server-side session
 * (audited), then 303 to the IdP end-session endpoint (SSO single sign-out) or the sign-in page.
 */
export async function POST(req: Request): Promise<Response> {
  try {
    requireSameOrigin(req);
  } catch (err: unknown) {
    if (err instanceof AuthError) return new NextResponse("Forbidden", { status: 403 });
    throw err;
  }
  const mode = authMode(env());
  const jar = await cookies();
  const token = jar.get(SESSION_COOKIE)?.value;
  let target: string | null = null;
  try {
    if (mode === "oidc") target = await logout(token);
    else if (mode === "local") await endSession(token);
  } catch (err: unknown) {
    console.error("[patchgate] logout failed:", describeError(err));
  }
  // Relative Location: correct behind the reverse proxy whatever internal host the request used.
  const res = new NextResponse(null, { status: 303, headers: { Location: target ?? "/login?signedOut=1", "Cache-Control": "no-store" } });
  res.cookies.delete({ name: SESSION_COOKIE, path: "/" });
  res.cookies.delete({ name: MFA_COOKIE, path: "/" });
  if (mode === "dev") res.cookies.delete({ name: DEV_USER_COOKIE, path: "/" });
  return res;
}
