import { z } from "zod";
import { cookies } from "next/headers";
import { prisma } from "@/lib/db";
import { env } from "@/lib/env";
import { AuthError, getCurrentUser, requireSameOrigin } from "@/lib/auth/session";
import { handle, ok } from "@/lib/api/response";
import { clientMeta } from "@/lib/auth/login-response";
import { auditTenantSwitch } from "@/lib/auth/vendor-access";
import { DomainError } from "@/lib/errors";
import { TENANT_COOKIE, isPlatformUser, isValidTenantId } from "@/lib/tenancy";

const bodySchema = z.object({
  // null = stop acting for a bank
  tenantId: z.string().refine(isValidTenantId, "invalid bank id").nullable(),
});

// Re-validated on every request anyway; this only bounds how long a forgotten choice lingers.
const COOKIE_MAX_AGE_SEC = 8 * 60 * 60;

/**
 * Bank switcher for OUR staff (tenantId = null): choose which bank the following requests act for.
 * Bank users can never switch (403). Same-origin only. Every switch is vendor access: audited on the platform
 * chain AND on the bank's own chain (entered / left) with role and client IP, so the bank's SIEM sees it.
 * Platform VIEWERs may switch too (read-only for the bank) — equally audited.
 */
export async function POST(req: Request): Promise<Response> {
  return handle(async () => {
    requireSameOrigin(req);
    const user = await getCurrentUser();
    if (!isPlatformUser(user)) throw new AuthError("Bank users cannot switch banks", 403);
    const { tenantId } = bodySchema.parse(await req.json());

    let bank: { id: string; slug: string; name: string } | null = null;
    if (tenantId) {
      bank = await prisma.tenant.findFirst({ where: { id: tenantId, active: true }, select: { id: true, slug: true, name: true } });
      if (!bank) throw new DomainError("Bank not found or suspended", 404);
    }

    const jar = await cookies();
    const prevId = jar.get(TENANT_COOKIE)?.value;
    const previous =
      prevId && isValidTenantId(prevId) ? await prisma.tenant.findUnique({ where: { id: prevId }, select: { id: true } }) : null;
    if (bank) {
      jar.set(TENANT_COOKIE, bank.id, {
        httpOnly: true,
        sameSite: "strict",
        secure: env().NODE_ENV === "production",
        path: "/",
        maxAge: COOKIE_MAX_AGE_SEC,
      });
    } else {
      jar.delete(TENANT_COOKIE);
    }

    await auditTenantSwitch(user, { bank, previousTenantId: previous?.id ?? null }, clientMeta(req).ip);
    return ok({ tenantId: bank?.id ?? null, name: bank?.name ?? null });
  });
}
