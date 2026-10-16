import { getCurrentUser } from "@/lib/auth/session";
import { NavLinks } from "./nav-links";

/**
 * Server wrapper for the (client) nav: resolves the signed-in user per request so platform staff
 * (tenantId = null) also get the Operations link. Rendered inside <Suspense> with NavLinksStatic as the
 * fallback, so the static shell stays prerenderable. Not signed in → the bank nav.
 */
export async function NavForUser({ variant }: { variant: "sidebar" | "top" }) {
  const user = await getCurrentUser().catch(() => null);
  return <NavLinks variant={variant} platformStaff={user !== null && user.tenantId === null} />;
}
