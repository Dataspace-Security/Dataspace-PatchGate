import "server-only";
import Link from "next/link";
import type { ReactNode } from "react";
import { getPageUser } from "@/lib/auth/page-user";
import { canRead, canWrite } from "@/lib/auth/roles";
import type { SessionUser } from "@/lib/auth/session";
import { Alert } from "@/components/ui";

export { ROLE_LABEL } from "@/lib/auth/roles";

/**
 * Server-side guard for /admin pages: signed in AND role ADMIN or AUDITOR (platform or bank).
 * readOnly = auditor: the page shows the lists but no forms or actions (the APIs refuse them anyway).
 */
export async function getAdminUser(): Promise<{ user: SessionUser; denied: ReactNode | null; readOnly: boolean }> {
  const user = await getPageUser();
  if (!canRead(user)) {
    return {
      user,
      readOnly: true,
      denied: (
        <Alert tone="bad">
          Administrators only. Ask your PatchGate administrator if you need access. <Link href="/" className="underline">Back to the dashboard</Link>
        </Alert>
      ),
    };
  }
  return { user, denied: null, readOnly: !canWrite(user) };
}

export function AdminTabs({ active, platform }: { active: "overview" | "users" | "banks"; platform: boolean }) {
  const tabs = [
    { key: "overview", href: "/admin", label: "Overview" },
    { key: "users", href: "/admin/users", label: "Users" },
    ...(platform ? [{ key: "banks", href: "/admin/banks", label: "Banks" }] : []),
  ];
  return (
    <nav aria-label="Administration" className="-mt-2 mb-6 flex gap-1 border-b border-border">
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
