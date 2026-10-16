import { NextResponse, connection } from "next/server";
import { authMode, env } from "@/lib/env";
import { LOGIN_COOKIE, LOGIN_TTL_MS, startLogin } from "@/lib/auth/oidc";
import { describeError } from "@/lib/errors-describe";

/** Start bank SSO: redirect to the IdP (authorization code + PKCE). */
export async function GET(req: Request): Promise<Response> {
  await connection(); // runtime config only — never read secrets during build/prerender
  const e = env();
  const mode = authMode(e);
  if (mode !== "oidc") {
    // Local accounts sign in on /login itself; the dev switcher exists only in development.
    return new NextResponse(null, { status: 303, headers: { Location: mode === "dev" ? "/dev-login" : "/login", "Cache-Control": "no-store" } });
  }
  try {
    const { url, loginCookie } = await startLogin(new URL(req.url).searchParams.get("returnTo"));
    const res = NextResponse.redirect(url);
    res.cookies.set(LOGIN_COOKIE, loginCookie, { httpOnly: true, secure: true, sameSite: "lax", path: "/", maxAge: LOGIN_TTL_MS / 1000 });
    res.headers.set("Cache-Control", "no-store");
    return res;
  } catch (err: unknown) {
    console.error("[patchgate] sso start failed:", describeError(err));
    return NextResponse.redirect(new URL("/login?error=unavailable", e.OIDC_REDIRECT_URI!));
  }
}
