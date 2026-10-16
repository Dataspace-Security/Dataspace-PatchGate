import { z } from "zod";
import { cookies } from "next/headers";
import { prisma } from "@/lib/db";
import { authMode, env } from "@/lib/env";
import { DEV_USER_COOKIE, requireSameOrigin } from "@/lib/auth/session";
import { fail, handle, ok } from "@/lib/api/response";

const bodySchema = z.object({ upn: z.string().min(3).max(200) });

/** DEVELOPMENT ONLY: switch the acting user to exercise maker-checker. 404 in any other mode. */
export async function POST(req: Request): Promise<Response> {
  return handle(async () => {
    if (env().NODE_ENV !== "development" || authMode() !== "dev") return fail("Not found", 404);
    requireSameOrigin(req);
    const { upn } = bodySchema.parse(await req.json());
    const user = await prisma.user.findUnique({ where: { upn } });
    if (!user || !user.active) return fail("Unknown user", 404);
    (await cookies()).set(DEV_USER_COOKIE, upn, { httpOnly: true, sameSite: "strict", path: "/" });
    return ok({ upn });
  });
}
