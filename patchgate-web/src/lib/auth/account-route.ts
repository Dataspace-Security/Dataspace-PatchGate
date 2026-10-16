import "server-only";
import { cookies } from "next/headers";
import type { z } from "zod";
import { fail, handle, ok } from "@/lib/api/response";
import type { AccountContext, AccountResult } from "./account-service";
import { clientMeta, guardLocalAuth } from "./login-response";
import { getCurrentUser } from "./session";
import type { ClientMeta } from "./session-store";
import { SESSION_COOKIE, sha256Hex } from "./tokens";

function noStore(res: Response): Response {
  res.headers.set("Cache-Control", "no-store");
  return res;
}

/**
 * Skeleton for /api/account/* (AUTH_MODE=local only, 404 otherwise): same-origin → live session →
 * zod-validated body → action. A result with signedOut=true also clears the session cookie.
 */
export async function accountRoute<I, T>(
  req: Request,
  schema: z.ZodType<I> | null,
  run: (ctx: AccountContext, input: I, meta: ClientMeta) => Promise<AccountResult<T>>,
): Promise<Response> {
  const blocked = guardLocalAuth(req);
  if (blocked) return blocked;
  return noStore(
    await handle(async () => {
      const user = await getCurrentUser();
      const token = (await cookies()).get(SESSION_COOKIE)?.value;
      if (!token) return fail("Not signed in", 401);
      const input = (schema ? schema.parse(await req.json().catch(() => null)) : undefined) as I;
      const r = await run({ userId: user.id, sessionId: sha256Hex(token) }, input, clientMeta(req));
      if (r.ok) return ok(r.data);
      const res = fail(r.error, r.status);
      if (r.signedOut) res.headers.append("Set-Cookie", `${SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`);
      return res;
    }),
  );
}
