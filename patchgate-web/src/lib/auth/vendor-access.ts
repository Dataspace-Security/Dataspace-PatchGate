import "server-only";
import { appendAudit } from "@/lib/audit/service";
import type { SessionUser } from "./session";

/**
 * PatchGate staff (platform users) acting for a bank is VENDOR ACCESS: the bank's SIEM must see it.
 * Every switch is written to the platform chain AND to the chain of the bank concerned (the bank entered,
 * or the bank left on "clear"), with who (UPN + role), and from where (client IP).
 */
export async function auditTenantSwitch(
  user: Pick<SessionUser, "upn" | "role">,
  change: { bank: { id: string; slug: string } | null; previousTenantId: string | null },
  ip: string | null,
): Promise<void> {
  const { bank, previousTenantId } = change;
  const action = bank ? "tenant.select" : "tenant.clear";
  const payload = { slug: bank?.slug ?? null, role: user.role, ip, vendorAccess: true, previousTenantId };
  await appendAudit({ actor: user.upn, action, entity: "Tenant", entityId: bank?.id ?? "-", payload, tenantId: null });

  const banks = new Set<string>();
  if (bank) banks.add(bank.id);
  if (previousTenantId && previousTenantId !== bank?.id) banks.add(previousTenantId);
  for (const tenantId of banks) {
    const entering = bank?.id === tenantId;
    await appendAudit({
      actor: user.upn,
      action: entering ? "tenant.select" : "tenant.clear",
      entity: "Tenant",
      entityId: tenantId,
      payload: { role: user.role, ip, vendorAccess: true, platformStaff: true },
      tenantId,
    });
  }
}
