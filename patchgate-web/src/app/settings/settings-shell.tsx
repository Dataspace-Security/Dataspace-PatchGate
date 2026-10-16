import "server-only";
import Link from "next/link";
import type { ReactNode } from "react";
import { canRead, canWrite } from "@/lib/auth/roles";
import type { SessionUser } from "@/lib/auth/session";
import type { ActiveTenant } from "@/lib/tenancy";
import { getPageTenant } from "@/lib/tenancy/page";
import { Alert } from "@/components/ui";

export type SettingsTab = "rings" | "windows" | "approvals" | "security" | "notifications";

/**
 * Bank settings pages: signed in + role ADMIN (edit) or AUDITOR (read-only), acting for the active bank
 * (bank user: own bank, platform staff: the bank picked in the switcher). The APIs enforce the same rule.
 */
export async function getSettingsContext(): Promise<{ user: SessionUser; tenant: ActiveTenant; denied: ReactNode | null; readOnly: boolean }> {
  const { user, tenant } = await getPageTenant();
  if (!canRead(user)) {
    return {
      user,
      tenant,
      readOnly: true,
      denied: (
        <Alert tone="bad">
          Bank settings are for administrators. <Link href="/" className="underline">Back to the dashboard</Link>
        </Alert>
      ),
    };
  }
  return { user, tenant, denied: null, readOnly: !canWrite(user) };
}

/** Shown on settings pages to auditors: values are visible, nothing can be changed. */
export function ReadOnlyNotice() {
  return <Alert tone="info">Read-only view (auditor): you can see these settings but cannot change them.</Alert>;
}

/**
 * Tabs of the ADVANCED settings group. Everything here has sensible defaults (three rings per bank, no
 * window = deploy when approved, one bank approver, notifications on): the normal flow is just
 * pick patches → create request → a bank admin approves → deploy.
 * `platformAdmin` = platform staff (admin or auditor): also shows the platform-wide account security tab.
 */
export function SettingsTabs({ active, platformAdmin }: { active: SettingsTab; platformAdmin: boolean }) {
  const tabs: { key: SettingsTab; href: string; label: string }[] = [
    { key: "rings", href: "/settings/rings", label: "Rings" },
    { key: "windows", href: "/settings/windows", label: "Maintenance windows" },
    { key: "approvals", href: "/settings/approvals", label: "Approval policy" },
    { key: "notifications", href: "/settings/notifications", label: "Notifications" },
    ...(platformAdmin ? [{ key: "security" as const, href: "/settings/security", label: "Account security" }] : []),
  ];
  return (
    <>
    <p className="-mt-2 mb-2 text-xs text-muted" data-testid="advanced-settings-hint">
      <span className="font-semibold uppercase tracking-wide">Advanced settings</span> — optional; the defaults work out of the box. Change them only when your bank needs to.
    </p>
    <nav aria-label="Advanced settings" className="mb-6 flex flex-wrap gap-1 border-b border-border">
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
    </>
  );
}
