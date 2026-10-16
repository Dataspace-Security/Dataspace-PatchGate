import "server-only";
import { redirect } from "next/navigation";
import { getPageUser } from "@/lib/auth/page-user";
import { AuthError, type SessionUser } from "@/lib/auth/session";
import { resolveActiveTenant, type ActiveTenant } from "./context";

export interface PageTenantContext {
  user: SessionUser;
  tenant: ActiveTenant;
}

/** Path platform staff are sent to when a bank-scoped page is opened without a bank selected. */
export const SELECT_BANK_PATH = "/select-bank";

/**
 * For bank-scoped pages: the signed-in user + the bank they act for.
 * Platform staff without a selected bank are redirected to the bank picker; a bank user whose bank is
 * suspended is sent back to sign-in.
 */
export async function getPageTenant(): Promise<PageTenantContext> {
  const user = await getPageUser();
  let tenant: ActiveTenant | null;
  try {
    tenant = await resolveActiveTenant(user);
  } catch (err: unknown) {
    if (err instanceof AuthError) redirect("/login?error=signin");
    throw err;
  }
  if (!tenant) redirect(SELECT_BANK_PATH);
  return { user, tenant };
}
