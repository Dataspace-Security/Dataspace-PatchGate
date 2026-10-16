import "server-only";
import { cookies } from "next/headers";
import { prisma } from "@/lib/db";
import { AuthError, type SessionUser } from "@/lib/auth/session";
import { TENANT_COOKIE, TenantRequiredError, isPlatformAdmin, requestedTenantId } from "./policy";

/** The bank a request acts for. */
export interface ActiveTenant {
  id: string;
  slug: string;
  name: string;
  requireBankApproval: boolean;
}

const TENANT_SELECT = { id: true, slug: true, name: true, requireBankApproval: true, active: true } as const;

/**
 * Resolve the active bank for the signed-in user.
 * - Bank user: always their own bank (cannot be overridden). A missing/suspended bank is a 403.
 * - Platform staff: the bank from the `pg_tenant` cookie, re-validated (exists + active) on every request;
 *   null when none is chosen (or the chosen bank was suspended / deleted since).
 */
export async function resolveActiveTenant(user: SessionUser): Promise<ActiveTenant | null> {
  const cookieValue = user.tenantId === null ? (await cookies()).get(TENANT_COOKIE)?.value : undefined;
  const id = requestedTenantId(user, cookieValue);
  if (!id) return null;
  const t = await prisma.tenant.findUnique({ where: { id }, select: TENANT_SELECT });
  if (!t || !t.active) {
    if (user.tenantId !== null) throw new AuthError("Your bank's access is suspended", 403);
    return null;
  }
  return { id: t.id, slug: t.slug, name: t.name, requireBankApproval: t.requireBankApproval };
}

/** Active bank or a clear 409 telling platform staff to pick one. */
export async function requireActiveTenant(user: SessionUser): Promise<ActiveTenant> {
  const t = await resolveActiveTenant(user);
  if (!t) throw new TenantRequiredError();
  return t;
}

/** Active bank id or a clear 409 (see requireActiveTenant). */
export async function requireTenant(user: SessionUser): Promise<string> {
  return (await requireActiveTenant(user)).id;
}

/** Platform-only operations (trust decisions, shared catalog). Bank admins get 403. */
export function requirePlatformAdmin(user: SessionUser): void {
  if (!isPlatformAdmin(user)) throw new AuthError("Platform administrators only", 403);
}

/** Banks a platform user can switch to (active only, by name). */
export async function listSelectableTenants(): Promise<{ id: string; name: string; slug: string }[]> {
  return prisma.tenant.findMany({ where: { active: true }, orderBy: { name: "asc" }, select: { id: true, name: true, slug: true } });
}
