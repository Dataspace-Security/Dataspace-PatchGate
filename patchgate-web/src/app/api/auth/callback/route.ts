import { NextResponse, connection } from "next/server";
import { cookies } from "next/headers";
import { authMode, env } from "@/lib/env";
import { LOGIN_COOKIE, SESSION_COOKIE, finishLogin } from "@/lib/auth/oidc";
import { clientIp } from "@/lib/ratelimit/limiter";

/** IdP redirect target: validate the code exchange + ID token, then issue a fresh server-side session. */
export async function GET(req: Request): Promise<Response> {
  await connection(); // runtime config only — never read secrets during build/prerender
  const e = env();
  if (authMode(e) !== "oidc") return new NextResponse("Not found", { status: 404 });
  const base = e.OIDC_REDIRECT_URI!; // public origin (the request may arrive via an internal name)
  const jar = await cookies();
  const outcome = await finishLogin(new URL(req.url), jar.get(LOGIN_COOKIE)?.value, {
    ip: clientIp(req.headers, e.TRUST_PROXY_HOPS),
    userAgent: req.headers.get("user-agent"),
  });

  const res = NextResponse.redirect(new URL(outcome.ok ? outcome.returnTo : `/login?error=${outcome.reason}`, base));
  res.cookies.delete({ name: LOGIN_COOKIE, path: "/" });
  if (outcome.ok) {
    // Session cookie: no Max-Age (dies with the browser); expiry is enforced server-side.
    res.cookies.set(SESSION_COOKIE, outcome.sessionToken, { httpOnly: true, secure: true, sameSite: "lax", path: "/" });
  }
  res.headers.set("Cache-Control", "no-store");
  return res;
}
