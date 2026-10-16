import { LogOut } from "lucide-react";

/** Plain form POST (no JavaScript needed): the server ends the session (audited), then shows sign-in or the IdP sign-out. */
export function SignOutButton() {
  return (
    <form method="post" action="/api/auth/logout" className="shrink-0">
      <button
        type="submit"
        title="Sign out"
        aria-label="Sign out"
        className="flex h-8 w-8 items-center justify-center rounded-lg text-sidebar-fg hover:bg-sidebar-active hover:text-white"
      >
        <LogOut size={16} />
      </button>
    </form>
  );
}
