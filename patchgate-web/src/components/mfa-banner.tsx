import { ShieldAlert } from "lucide-react";
import { MFA_OFF_WARNING } from "@/lib/auth/mfa-status";
import { isAdmin } from "@/lib/auth/roles";
import { getCurrentUser } from "@/lib/auth/session";
import { mfaDisabled } from "@/lib/env";

/** Warning strip for ADMIN users while local sign-in runs without the TOTP code (AUTH_MFA=off). */
export async function MfaOffBanner() {
  const user = await getCurrentUser().catch(() => null); // per request (connection()), never prerendered
  if (!user || !isAdmin(user) || !mfaDisabled()) return null;
  return (
    <div role="alert" data-testid="mfa-off-banner" className="mb-6 flex items-center gap-2 rounded-lg border border-warning/40 bg-warning-soft px-4 py-3 text-sm font-medium text-warning">
      <ShieldAlert size={16} aria-hidden className="shrink-0" />
      {MFA_OFF_WARNING}
    </div>
  );
}
