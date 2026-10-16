/**
 * Pure tenancy rules (no I/O), shared by the request layer, services and tests.
 *
 * - A user with tenantId = null is OUR team (platform staff). They act for one bank at a time: the bank
 *   chosen with the switcher (cookie `pg_tenant`, re-validated on every request).
 * - A user with a tenantId belongs to that bank and ALWAYS acts for it; the cookie is ignored for them.
 */
import { DomainError } from "@/lib/errors";

/** Cookie holding the bank a platform user is acting for (value = Tenant.id). */
export const TENANT_COOKIE = "pg_tenant";

// cuid() ids and seeded ids like "tenant-default"; anything else is rejected before touching the DB.
const TENANT_ID_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;

export function isValidTenantId(id: unknown): id is string {
  return typeof id === "string" && TENANT_ID_RE.test(id);
}

export interface TenantUser {
  role: "VIEWER" | "OPERATOR" | "APPROVER" | "ADMIN";
  tenantId: string | null;
}

export function isPlatformUser(user: TenantUser): boolean {
  return user.tenantId === null;
}

/** Trust decisions, the shared catalog and bank onboarding: our admins only. */
export function isPlatformAdmin(user: TenantUser): boolean {
  return user.tenantId === null && user.role === "ADMIN";
}

/**
 * Which bank id the request should be scoped to, BEFORE the DB check:
 * bank user → own bank (cookie ignored); platform user → the cookie value if well-formed, else none.
 */
export function requestedTenantId(user: TenantUser, cookieValue: string | undefined): string | null {
  if (user.tenantId !== null) return user.tenantId;
  return isValidTenantId(cookieValue) ? cookieValue : null;
}

/** May this user act for that bank at all? (Bank users: only their own. Platform staff: any.) */
export function canActForTenant(user: TenantUser, tenantId: string): boolean {
  return user.tenantId === null || user.tenantId === tenantId;
}

/**
 * Object-level check: the row must belong to the active bank. A mismatch is reported as "not found"
 * (404) so a bank can never probe for the existence of another bank's objects.
 */
export function assertSameTenant(activeTenantId: string, rowTenantId: string | null | undefined, what = "Resource"): void {
  if (!rowTenantId || rowTenantId !== activeTenantId) throw new DomainError(`${what} not found`, 404);
}

/** Thrown when platform staff call a bank-scoped API without having picked a bank. */
export class TenantRequiredError extends DomainError {
  constructor() {
    super("Select a bank first (bank switcher in the sidebar)", 409);
    this.name = "TenantRequiredError";
  }
}
