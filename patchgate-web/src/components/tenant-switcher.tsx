import { Building2 } from "lucide-react";
import { getCurrentUser, type SessionUser } from "@/lib/auth/session";
import { listSelectableTenants, resolveActiveTenant, type ActiveTenant } from "@/lib/tenancy";
import { TenantSelect } from "./tenant-select";

async function tryContext(): Promise<{ user: SessionUser; active: ActiveTenant | null } | null> {
  try {
    const user = await getCurrentUser();
    return { user, active: await resolveActiveTenant(user) };
  } catch {
    return null;
  }
}

/**
 * Sidebar block showing which bank the user acts for.
 * Platform staff get a switcher; bank users just see their bank (they can never change it).
 */
export async function TenantSwitcher() {
  const ctx = await tryContext();
  if (!ctx) return null;

  if (ctx.user.tenantId !== null) {
    return (
      <div className="flex items-center gap-2 px-1 text-sm text-white" title="Your bank">
        <Building2 size={15} className="shrink-0 text-sidebar-fg" aria-hidden />
        <span className="truncate">{ctx.active?.name ?? "Bank suspended"}</span>
      </div>
    );
  }

  const tenants = await listSelectableTenants();
  return (
    <div className="space-y-1.5">
      <p className="flex items-center gap-1.5 px-1 text-[11px] uppercase tracking-widest text-sidebar-fg">
        <Building2 size={12} aria-hidden /> Acting for bank
      </p>
      <TenantSelect tenants={tenants.map((t) => ({ id: t.id, name: t.name }))} activeId={ctx.active?.id ?? null} />
    </div>
  );
}
