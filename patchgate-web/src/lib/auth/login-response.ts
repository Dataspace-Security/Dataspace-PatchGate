import "server-only";
import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import type { z } from "zod";
import { authMode, env } from "@/lib/env";
import { describeError } from "@/lib/errors-describe";
import { clientIp } from "@/lib/ratelimit/limiter";
import { AuthError, requireSameOrigin } from "./session";
import { CHALLENGE_TTL_MS, type LoginStep } from "./local-login";
import type { ClientMeta } from "./session-store";
import { MFA_COOKIE, SESSION_COOKIE } from "./tokens";

/** What the browser sees for each local sign-in step (never the raw challenge or session tokens). */
export type LoginStepView =
  | { step: "verify" }
  | { step: "enroll"; secret: string; otpauthUri: string; qrSvgDataUrl: string }
  | { step: "change-password" }
  | { step: "done"; redirect: string };

function json(body: unknown, status: number): NextResponse {
  const res = NextResponse.json(body, { status });
  res.headers.set("Cache-Control", "no-store");
  return res;
}

export function failJson(error: string, status: number): NextResponse {
  return json({ success: false, data: null, error }, status);
}

/** Map a LoginStep to the JSON envelope + cookies (challenge cookie between steps, session cookie at the end). */
export function loginStepResponse(r: LoginStep): NextResponse {
  if (!r.ok) {
    const res = failJson(r.error, r.status);
    if (r.restart) res.cookies.delete({ name: MFA_COOKIE, path: "/" });
    return res;
  }
  if (r.step === "done") {
    const res = json({ success: true, data: { step: "done", redirect: r.returnTo } satisfies LoginStepView, error: null }, 200);
    res.cookies.delete({ name: MFA_COOKIE, path: "/" });
    // No Max-Age (dies with the browser); idle + absolute expiry are enforced server-side.
    res.cookies.set(SESSION_COOKIE, r.sessionToken, { httpOnly: true, secure: true, sameSite: "lax", path: "/" });
    return res;
  }
  const view: LoginStepView =
    r.step === "enroll" ? { step: "enroll", secret: r.secret, otpauthUri: r.otpauthUri, qrSvgDataUrl: r.qrSvgDataUrl } : { step: r.step };
  const res = json({ success: true, data: view, error: null }, 200);
  res.cookies.set(MFA_COOKIE, r.challengeToken, { httpOnly: true, secure: true, sameSite: "lax", path: "/", maxAge: CHALLENGE_TTL_MS / 1000 });
  return res;
}

/** Shared guard for the local sign-in endpoints: local mode only (404 otherwise) + same-origin. */
export function guardLocalAuth(req: Request): NextResponse | null {
  if (authMode() !== "local") return failJson("Not found", 404);
  try {
    requireSameOrigin(req);
  } catch (err: unknown) {
    if (err instanceof AuthError) return failJson(err.message, err.status);
    throw err;
  }
  return null;
}

export function clientMeta(req: Request): ClientMeta {
  return { ip: clientIp(req.headers, env().TRUST_PROXY_HOPS), userAgent: req.headers.get("user-agent") };
}

/** Route skeleton for a local sign-in step: guard → zod-validated body → step → cookies + envelope. */
export async function localAuthRoute<T>(
  req: Request,
  schema: z.ZodType<T>,
  run: (input: T, ctx: { meta: ClientMeta; mfaToken: string | undefined }) => Promise<LoginStep>,
): Promise<Response> {
  const blocked = guardLocalAuth(req);
  if (blocked) return blocked;
  const parsed = schema.safeParse(await req.json().catch(() => null));
  if (!parsed.success) {
    const first = parsed.error.issues[0];
    return failJson(`Invalid request — ${first?.path.join(".") || "body"}: ${first?.message ?? "malformed"}`, 400);
  }
  try {
    const mfaToken = (await cookies()).get(MFA_COOKIE)?.value;
    return loginStepResponse(await run(parsed.data, { meta: clientMeta(req), mfaToken }));
  } catch (err: unknown) {
    console.error("[patchgate] local sign-in step failed:", describeError(err));
    return failJson("Sign-in is temporarily unavailable. Please try again.", 500);
  }
}
