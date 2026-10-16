import { redirect } from "next/navigation";
import { Suspense } from "react";
import { getPageUser } from "@/lib/auth/page-user";
import { listSelectableTenants, resolveActiveTenant } from "@/lib/tenancy";
import { TenantSelect } from "@/components/tenant-select";
import { Alert, Card, EmptyState, Loading, PageHeader } from "@/components/ui";

/** Platform staff land here when they open a bank-scoped page without having chosen a bank. */
async function Picker() {
  const user = await getPageUser();
  if (user.tenantId !== null) redirect("/"); // bank users always act for their own bank
  const [tenants, active] = await Promise.all([listSelectableTenants(), resolveActiveTenant(user)]);
  if (tenants.length === 0) {
    return <EmptyState title="No active banks">Onboard a bank under Admin first.</EmptyState>;
  }
  return (
    <Card title="Act for bank" description="Endpoints, change requests, discovery and the audit chain are shown for one bank at a time.">
      <div className="max-w-md space-y-3">
        <TenantSelect tenants={tenants.map((t) => ({ id: t.id, name: t.name }))} activeId={active?.id ?? null} variant="page" />
        <Alert tone="info">Every switch is recorded in the platform audit chain.</Alert>
      </div>
    </Card>
  );
}

export default function SelectBankPage() {
  return (
    <div className="max-w-3xl">
      <PageHeader title="Select a bank" description="You are signed in as PatchGate staff. Choose the bank you are working for." />
      <Suspense fallback={<Loading />}>
        <Picker />
      </Suspense>
    </div>
  );
}
