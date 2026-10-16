import "server-only";
import type { SessionUser } from "@/lib/auth/session";
import { resolveActiveTenant, type ActiveTenant } from "@/lib/tenancy";

export interface AuditChainScope {
  /** Chain to show: bank id, or null = platform chain */
  tenantId: string | null;
  /** The bank, when a bank chain is shown */
  tenant: ActiveTenant | null;
  /** Only our staff may look at the platform chain */
  canViewPlatform: boolean;
}

/**
 * Which audit chain a user may read:
 * - bank user → their bank's chain, always (a `chain=platform` request is ignored);
 * - platform staff → the platform chain when asked for (or when no bank is selected), else the active bank's.
 */
export async function resolveAuditChain(user: SessionUser, requested: string | null | undefined): Promise<AuditChainScope> {
  const tenant = await resolveActiveTenant(user);
  if (user.tenantId !== null) return { tenantId: tenant?.id ?? user.tenantId, tenant, canViewPlatform: false };
  if (requested === "platform" || !tenant) return { tenantId: null, tenant: null, canViewPlatform: true };
  return { tenantId: tenant.id, tenant, canViewPlatform: true };
}
