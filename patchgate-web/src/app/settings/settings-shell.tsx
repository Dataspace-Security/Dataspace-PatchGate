import "server-only";
import Link from "next/link";
import type { ReactNode } from "react";
import type { SessionUser } from "@/lib/auth/session";
import type { ActiveTenant } from "@/lib/tenancy";
import { getPageTenant } from "@/lib/tenancy/page";
import { Alert } from "@/components/ui";

export type SettingsTab = "rings" | "windows" | "approvals" | "security" | "notifications";

/**
 * Bank settings pages: signed in + role ADMIN, acting for the active bank (bank admin: own bank,
 * platform admin: the bank picked in the switcher). The APIs enforce the same rule server-side.
 */
export async function getSettingsContext(): Promise<{ user: SessionUser; tenant: ActiveTenant; denied: ReactNode | null }> {
  const { user, tenant } = await getPageTenant();
  if (user.role !== "ADMIN") {
    return {
      user,
      tenant,
      denied: (
        <Alert tone="bad">
          Bank settings are for administrators. <Link href="/" className="underline">Back to the dashboard</Link>
        </Alert>
      ),
    };
  }
  return { user, tenant, denied: null };
}

export function SettingsTabs({ active, platformAdmin }: { active: SettingsTab; platformAdmin: boolean }) {
  const tabs: { key: SettingsTab; href: string; label: string }[] = [
    { key: "rings", href: "/settings/rings", label: "Rings" },
    { key: "windows", href: "/settings/windows", label: "Maintenance windows" },
    { key: "approvals", href: "/settings/approvals", label: "Approval policy" },
    { key: "notifications", href: "/settings/notifications", label: "Notifications" },
    ...(platformAdmin ? [{ key: "security" as const, href: "/settings/security", label: "Account security" }] : []),
  ];
  return (
    <nav aria-label="Settings" className="-mt-2 mb-6 flex flex-wrap gap-1 border-b border-border">
      {tabs.map((t) => (
        <Link
          key={t.key}
          href={t.href}
          aria-current={t.key === active ? "page" : undefined}
          className="-mb-px border-b-2 border-transparent px-3 py-2 text-sm font-medium text-muted hover:text-fg aria-[current=page]:border-primary aria-[current=page]:text-fg"
        >
          {t.label}
        </Link>
      ))}
    </nav>
  );
}
