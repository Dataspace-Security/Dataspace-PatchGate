import { getCurrentUser, requireSameOrigin, requireWriter } from "@/lib/auth/session";
import { handle, ok } from "@/lib/api/response";
import { appendAudit } from "@/lib/audit/service";
import { tenantUsesConnector } from "@/lib/connector/routing";
import { requestConnectorScan } from "@/lib/scan/scan-request";
import { requireTenant, withTenant } from "@/lib/tenancy";

/**
 * "Request scan of all PCs" (ADMIN only, audited).
 * Connector banks: sync the agent list from Tactical first (PCs Tactical just enrolled are included), mark
 * every PC due (SCAN + COLLECT) and, when Windows updates come through PatchGate, an offline WU_SCAN after
 * the sync (src/lib/scan/scan-request.ts). Legacy direct-Tactical bank: mark the endpoints due.
 */
export async function POST(req: Request): Promise<Response> {
  return handle(async () => {
    requireSameOrigin(req);
    const user = await getCurrentUser();
    requireWriter(user);
    const tenantId = await requireTenant(user);
    if (await tenantUsesConnector(tenantId)) return ok(await requestConnectorScan(tenantId, user.upn));
    const count = await withTenant(tenantId, async (tx) => {
      const r = await tx.endpoint.updateMany({ where: { tenantId }, data: { lastScanRequestedAt: null, lastScanAt: null } });
      await appendAudit(
        { tenantId, actor: user.upn, action: "endpoints.scan_requested", entity: "Endpoint", entityId: "*", payload: { count: r.count } },
        tx,
      );
      return r.count;
    });
    return ok({ queued: count, message: "Scan requested — results appear after the next worker rounds." });
  });
}
