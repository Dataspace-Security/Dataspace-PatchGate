import { Suspense } from "react";
import { getBankPolicy } from "@/lib/policies/bank-settings";
import { Loading, PageHeader } from "@/components/ui";
import { SettingsTabs, getSettingsContext } from "../settings-shell";
import { ApprovalPolicyForm } from "./approval-form";

async function Approvals() {
  const { user, tenant, denied } = await getSettingsContext();
  const header = (
    <>
      <PageHeader
        title="Approval policy"
        description={`How change requests of ${tenant.name} are approved. Maker and checker are always different people; emergency changes always need two distinct approvers.`}
      />
      <SettingsTabs active="approvals" platformAdmin={user.tenantId === null && user.role === "ADMIN"} />
    </>
  );
  if (denied) return <>{header}{denied}</>;
  const policy = await getBankPolicy(tenant.id);
  return (
    <>
      {header}
      <ApprovalPolicyForm initial={policy} />
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
