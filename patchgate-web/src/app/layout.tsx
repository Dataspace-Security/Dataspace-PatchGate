import type { Metadata } from "next";
import { Suspense } from "react";
import { ShieldCheck } from "lucide-react";
import { CurrentUser } from "@/components/current-user";
import { NavForUser } from "@/components/nav-for-user";
import { NavLinksStatic } from "@/components/nav-links";
import { TenantSwitcher } from "@/components/tenant-switcher";
import { THEME_BOOT_SCRIPT, ThemeToggle } from "@/components/theme-toggle";
import { buildInfo, versionLabel } from "@/lib/version";
import "./globals.css";

// System fonts only: no build-time font downloads (bank builds may be offline).

export const metadata: Metadata = {
  title: "PatchGate — Dataspace Security",
  description: "Approval-gated patch management for offline bank endpoints",
};

function Brand() {
  return (
    <div className="flex items-center gap-2.5">
      <span className="flex h-9 w-9 items-center justify-center rounded-lg bg-gradient-to-br from-primary to-accent text-white shadow-sm">
        <ShieldCheck size={20} />
      </span>
      <span className="leading-tight">
        <span className="block text-base font-semibold text-white">PatchGate</span>
        <span className="block text-[11px] uppercase tracking-widest text-sidebar-fg">Dataspace Security</span>
      </span>
    </div>
  );
}

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en" className="h-full antialiased" data-theme="light" suppressHydrationWarning>
      <head>
        {/* Apply the saved / OS theme before first paint (no flash). */}
        <script dangerouslySetInnerHTML={{ __html: THEME_BOOT_SCRIPT }} />
      </head>
      <body className="min-h-full bg-bg font-sans text-fg">
        <div className="flex min-h-screen">
          {/* Sidebar (desktop) */}
          <div className="hidden w-64 shrink-0 border-r border-white/5 bg-sidebar lg:block">
          <aside className="sticky top-0 flex h-screen flex-col justify-between py-5">
            <div className="space-y-8">
              <div className="space-y-5 px-5">
                <Brand />
                <Suspense fallback={<span className="block h-14" />}>
                  <TenantSwitcher />
                </Suspense>
              </div>
              <Suspense fallback={<NavLinksStatic variant="sidebar" />}>
                <NavForUser variant="sidebar" />
              </Suspense>
            </div>
            <div className="space-y-3 border-t border-white/10 px-4 pt-4">
              <div className="flex items-center justify-between gap-2">
                <Suspense fallback={<span className="h-8" />}>
                  <CurrentUser />
                </Suspense>
                <ThemeToggle />
              </div>
              <p className="px-1 text-[11px] text-sidebar-fg/70">Offline zone: Tactical &amp; PCs have no internet.</p>
              <p className="px-1 font-mono text-[10px] text-sidebar-fg/50" title={`Build ${buildInfo().buildId} · connector protocol v${buildInfo().protocolVersion}`}>
                PatchGate {versionLabel()}
              </p>
            </div>
          </aside>
          </div>

          <div className="flex min-w-0 flex-1 flex-col">
            {/* Top bar (mobile / tablet) */}
            <header className="sticky top-0 z-10 bg-sidebar lg:hidden">
              <div className="flex items-center justify-between px-4 py-3">
                <Brand />
                <div className="flex items-center gap-2">
                  <Suspense fallback={null}>
                    <CurrentUser />
                  </Suspense>
                  <ThemeToggle />
                </div>
              </div>
              <div className="px-4 pb-2">
                <Suspense fallback={null}>
                  <TenantSwitcher />
                </Suspense>
              </div>
              <Suspense fallback={<NavLinksStatic variant="top" />}>
                <NavForUser variant="top" />
              </Suspense>
            </header>

            <main className="mx-auto w-full max-w-7xl flex-1 px-4 py-8 sm:px-8">
              {children}
            </main>
          </div>
        </div>
      </body>
    </html>
  );
}
