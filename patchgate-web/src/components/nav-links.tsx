"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Activity, AppWindow, FileBarChart, Cable, FileCheck2, LayoutDashboard, Monitor, Package, Radar, ScrollText, Settings, SlidersHorizontal } from "lucide-react";

export const NAV = [
  { href: "/", label: "Dashboard", icon: LayoutDashboard },
  { href: "/patches", label: "Patches", icon: Package },
  { href: "/change-requests", label: "Change requests", icon: FileCheck2 },
  { href: "/endpoints", label: "Endpoints", icon: Monitor },
  { href: "/discovery", label: "Discovery", icon: Radar },
  { href: "/apps", label: "Apps & mirror", icon: AppWindow },
  { href: "/connectors", label: "Connectors", icon: Cable },
  { href: "/audit", label: "Audit", icon: ScrollText },
  { href: "/reports", label: "Reports", icon: FileBarChart },
  // ONE entry for everything optional (rings, windows, approval policy, notifications, account security):
  // the normal flow needs none of it. The /settings pages enforce their own access rules.
  { href: "/settings/rings", label: "Advanced settings", icon: SlidersHorizontal },
  // Shown to everyone; the /admin pages enforce their own access rules.
  { href: "/admin", label: "Admin", icon: Settings },
] as const;

/** Cross-bank operations view: listed for platform staff only (the page itself also refuses bank users). */
export const PLATFORM_NAV = [{ href: "/operations", label: "Operations", icon: Activity }] as const;

interface NavProps {
  variant: "sidebar" | "top";
  /** Signed-in user is PatchGate platform staff (tenantId = null): adds PLATFORM_NAV. */
  platformStaff?: boolean;
}

function linksFor(platformStaff: boolean | undefined) {
  return platformStaff ? [...NAV, ...PLATFORM_NAV] : NAV;
}

function isActive(pathname: string, href: string): boolean {
  return href === "/" ? pathname === "/" : pathname === href || pathname.startsWith(`${href}/`);
}

/** Vertical nav for the sidebar (lg+) and a horizontal scroller for small screens. */
export function NavLinks({ variant, platformStaff }: NavProps) {
  const pathname = usePathname();
  return <NavList variant={variant} pathname={pathname} platformStaff={platformStaff} />;
}

/** Same links without an active marker — prerendered shell / Suspense fallback. */
export function NavLinksStatic({ variant, platformStaff }: NavProps) {
  return <NavList variant={variant} pathname="" platformStaff={platformStaff} />;
}

function NavList({ variant, pathname, platformStaff }: NavProps & { pathname: string }) {
  const links = linksFor(platformStaff);
  if (variant === "top") {
    return (
      <nav aria-label="Main" className="flex gap-1 overflow-x-auto px-3 pb-2">
        {links.map(({ href, label, icon: Icon }) => (
          <Link
            key={href}
            href={href}
            aria-current={isActive(pathname, href) ? "page" : undefined}
            className="flex shrink-0 items-center gap-1.5 rounded-lg px-3 py-1.5 text-sm text-sidebar-fg aria-[current=page]:bg-sidebar-active aria-[current=page]:text-white"
          >
            <Icon size={15} />
            {label}
          </Link>
        ))}
      </nav>
    );
  }
  return (
    <nav aria-label="Main" className="flex flex-col gap-1 px-3">
      {links.map(({ href, label, icon: Icon }) => (
        <Link
          key={href}
          href={href}
          aria-current={isActive(pathname, href) ? "page" : undefined}
          className="group relative flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium text-sidebar-fg transition-colors hover:bg-sidebar-active hover:text-white aria-[current=page]:bg-sidebar-active aria-[current=page]:text-white"
        >
          <span
            aria-hidden
            className="absolute inset-y-1.5 left-0 w-0.5 rounded-full bg-accent opacity-0 group-aria-[current=page]:opacity-100"
          />
          <Icon size={17} className="opacity-80 group-aria-[current=page]:text-accent group-aria-[current=page]:opacity-100" />
          {label}
        </Link>
      ))}
    </nav>
  );
}
