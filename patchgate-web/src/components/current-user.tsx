import Link from "next/link";
import { UserRound } from "lucide-react";
import { getCurrentUser, type SessionUser } from "@/lib/auth/session";
import { authMode } from "@/lib/env";
import { SignOutButton } from "./sign-out-button";

async function tryGetUser(): Promise<SessionUser | null> {
  try {
    return await getCurrentUser();
  } catch {
    return null;
  }
}

function initials(name: string): string {
  return name
    .split(/\s+/)
    .map((p) => p[0])
    .join("")
    .slice(0, 2)
    .toUpperCase();
}

/** Identity chip for the sidebar footer: links to "My account" (/account); sign-out for real sessions (local / SSO); the user switcher in dev mode. */
export async function CurrentUser() {
  const u = await tryGetUser();
  if (!u) {
    return (
      <Link href="/login" className="text-sm font-medium text-white hover:underline">
        Sign in
      </Link>
    );
  }

  const chip = (
    <span className="flex min-w-0 items-center gap-2.5">
      <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-primary text-xs font-semibold text-primary-fg">
        {initials(u.name)}
      </span>
      <span className="min-w-0">
        <span className="block truncate text-sm font-medium text-white">{u.name}</span>
        <span className="block text-xs capitalize text-sidebar-fg">{u.role.toLowerCase()}</span>
      </span>
    </span>
  );
  if (authMode() !== "dev") {
    return (
      <span className="flex min-w-0 items-center gap-1">
        <Link href="/account" title="My account" aria-label={`My account (${u.name})`} className="min-w-0 flex-1 rounded-lg p-1 hover:bg-sidebar-active">
          {chip}
        </Link>
        <SignOutButton />
      </span>
    );
  }
  return (
    <span className="flex min-w-0 items-center gap-1">
      <Link href="/dev-login" title="Switch dev user" className="block min-w-0 flex-1 rounded-lg p-1 hover:bg-sidebar-active">
        {chip}
      </Link>
      <Link
        href="/account"
        title="My account"
        aria-label="My account"
        className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg text-sidebar-fg hover:bg-sidebar-active hover:text-white"
      >
        <UserRound size={16} />
      </Link>
    </span>
  );
}
