import { Suspense } from "react";
import { getPageUser } from "@/lib/auth/page-user";
import { securityPolicyView } from "@/lib/policies/security-store";
import { Alert, Loading, PageHeader, fmtDate } from "@/components/ui";
import { canWrite, isPlatformReader } from "@/lib/auth/roles";
import { ReadOnlyNotice, SettingsTabs } from "../settings-shell";
import { SecurityPolicyForm } from "./security-form";

async function Security() {
  const user = await getPageUser();
  const platformStaff = isPlatformReader(user);
  const readOnly = !canWrite(user);
  const header = (
    <>
      <PageHeader title="Account security" description="Platform-wide sign-in policies for every PatchGate user (our team and all banks)." />
      <SettingsTabs active="security" platformAdmin={platformStaff} />
    </>
  );
  if (!platformStaff) return <>{header}<Alert tone="bad">Only PatchGate platform staff see the account security policies.</Alert></>;
  const view = await securityPolicyView();
  return (
    <>
      {header}
      <div className="space-y-4">
        {readOnly && <ReadOnlyNotice />}
        <fieldset disabled={readOnly}>
        <SecurityPolicyForm
          initial={{ passwordMaxAgeDays: view.passwordMaxAgeDays, inactivityDisableDays: view.inactivityDisableDays, maxSessionsPerUser: view.maxSessionsPerUser }}
          sessionIdleMinutes={view.sessionIdleMinutes}
          sessionMaxHours={view.sessionMaxHours}
        />
        </fieldset>
        <p className="text-xs text-muted">
          Last changed {fmtDate(view.updatedAt)}
          {view.updatedBy ? ` by ${view.updatedBy}` : ""}. Every change is recorded on the platform audit chain.
        </p>
      </div>
    </>
  );
}

export default function SecuritySettingsPage() {
  return (
    <Suspense fallback={<Loading />}>
      <Security />
    </Suspense>
  );
}
