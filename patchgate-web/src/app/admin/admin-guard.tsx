import "server-only";
import Link from "next/link";
import type { ReactNode } from "react";
import { getPageUser } from "@/lib/auth/page-user";
import type { SessionUser } from "@/lib/auth/session";
import { Alert } from "@/components/ui";

export const ROLE_LABEL: Record<SessionUser["role"], string> = {
  ADMIN: "Admin",
  APPROVER: "Approver (checker)",
  OPERATOR: "Operator (maker)",
  VIEWER: "Viewer",
};

/** Server-side guard for /admin pages: signed in AND role ADMIN (platform or bank). */
export async function getAdminUser(): Promise<{ user: SessionUser; denied: ReactNode | null }> {
  const user = await getPageUser();
  if (user.role !== "ADMIN") {
    return {
      user,
      denied: (
        <Alert tone="bad">
          Administrators only. Ask your PatchGate administrator if you need access. <Link href="/" className="underline">Back to the dashboard</Link>
        </Alert>
      ),
    };
  }
  return { user, denied: null };
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
