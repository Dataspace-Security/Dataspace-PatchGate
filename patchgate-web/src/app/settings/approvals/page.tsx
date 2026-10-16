import { Suspense } from "react";
import { getBankPolicy } from "@/lib/policies/bank-settings";
import { Loading, PageHeader } from "@/components/ui";
import { isPlatformReader } from "@/lib/auth/roles";
import { ReadOnlyNotice, SettingsTabs, getSettingsContext } from "../settings-shell";
import { ApprovalPolicyForm } from "./approval-form";

async function Approvals() {
  const { user, tenant, denied, readOnly } = await getSettingsContext();
  const header = (
    <>
      <PageHeader
        title="Approval policy"
        description={`How change requests of ${tenant.name} are approved. A ${tenant.name} admin always approves; maker and checker are always different people; emergency changes always need two distinct admins.`}
      />
      <SettingsTabs active="approvals" platformAdmin={isPlatformReader(user)} />
    </>
  );
  if (denied) return <>{header}{denied}</>;
  const policy = await getBankPolicy(tenant.id);
  return (
    <>
      {header}
      {readOnly && <ReadOnlyNotice />}
      <fieldset disabled={readOnly} className={readOnly ? "mt-4 opacity-80" : undefined}>
        <ApprovalPolicyForm initial={policy} />
      </fieldset>
    </>
  );
}

export default function ApprovalSettingsPage() {
  return (
    <Suspense fallback={<Loading />}>
      <Approvals />
    </Suspense>
  );
}
