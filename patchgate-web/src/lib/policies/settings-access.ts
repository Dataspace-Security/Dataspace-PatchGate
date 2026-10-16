import "server-only";
import { AuthError, type SessionUser } from "@/lib/auth/session";
import { requireTenant } from "@/lib/tenancy";

/**
 * Bank self-service settings (rings, windows, approval policy, reboot defaults): role ADMIN, acting for
 * the active bank — a bank admin always for their own bank, a platform admin for the bank selected in the
 * switcher. Returns that bank's id. Everything else (operators, approvers, viewers) gets 403.
 */
export async function requireSettingsAdmin(user: SessionUser): Promise<string> {
  if (user.role !== "ADMIN") throw new AuthError("Bank settings are for administrators only", 403);
  return requireTenant(user);
}
