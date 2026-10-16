import "server-only";
import { canRead, canWrite } from "@/lib/auth/roles";
import { AuthError, type SessionUser } from "@/lib/auth/session";
import { requireTenant } from "@/lib/tenancy";

/**
 * Bank self-service settings (rings, windows, approval policy, reboot defaults): role ADMIN, acting for
 * the active bank — a bank admin always for their own bank, a platform admin for the bank selected in the
 * switcher. Returns that bank's id. Auditors get 403 here (they may only READ: requireSettingsReader).
 */
export async function requireSettingsAdmin(user: SessionUser): Promise<string> {
  if (!canWrite(user)) throw new AuthError("Bank settings are for administrators only", 403);
  return requireTenant(user);
}

/** Read the active bank's settings: admins and auditors (read-only). Returns that bank's id. */
export async function requireSettingsReader(user: SessionUser): Promise<string> {
  if (!canRead(user)) throw new AuthError("Bank settings are for administrators and auditors only", 403);
  return requireTenant(user);
}
