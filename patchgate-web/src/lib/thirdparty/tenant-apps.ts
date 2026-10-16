import "server-only";
import { appendAudit } from "@/lib/audit/service";
import { DomainError } from "@/lib/errors";
import { withTenant } from "@/lib/tenancy";

/**
 * A bank opts in to (or out of) a shared, verified third-party app (TenantApp).
 * Only enabled apps count for the bank's compliance, can be put in its change requests, and show as
 * "managed" in its discovery list. Disabling never touches the shared catalog or other banks.
 */
export async function setTenantAppEnabled(tenantId: string, appId: string, enabled: boolean, actorUpn: string): Promise<{ appId: string; enabled: boolean }> {
  return withTenant(tenantId, async (tx) => {
    const app = await tx.app.findUnique({ where: { id: appId }, select: { id: true, wingetId: true } });
    if (!app) throw new DomainError("App not found", 404);
    const current = await tx.tenantApp.findUnique({ where: { tenantId_appId: { tenantId, appId } } });
    if (Boolean(current) === enabled) return { appId, enabled }; // idempotent, nothing to audit

    if (enabled) {
      await tx.tenantApp.create({ data: { tenantId, appId, enabledBy: actorUpn } });
      // Link the bank's discovered products for this package straight away (the next rebuild would too).
      await tx.discoveredApp.updateMany({
        where: { tenantId, appId: null, wingetId: { equals: app.wingetId, mode: "insensitive" } },
        data: { appId, ignored: false },
      });
    } else {
      await tx.tenantApp.delete({ where: { tenantId_appId: { tenantId, appId } } });
      await tx.discoveredApp.updateMany({ where: { tenantId, appId }, data: { appId: null } });
    }
    await appendAudit(
      {
        tenantId,
        actor: actorUpn,
        action: enabled ? "tenant_app.enable" : "tenant_app.disable",
        entity: "App",
        entityId: appId,
        payload: { wingetId: app.wingetId },
      },
      tx,
    );
    return { appId, enabled };
  });
}
