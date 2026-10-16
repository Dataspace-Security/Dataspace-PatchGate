import { getCurrentUser, requireSameOrigin, requireWriter } from "@/lib/auth/session";
import { handle, ok } from "@/lib/api/response";
import { appendAudit } from "@/lib/audit/service";
import { requireTenant, withTenant } from "@/lib/tenancy";

/** Mark the active bank's endpoints as due: the worker requests a rescan and re-reads results on its next ticks. */
export async function POST(req: Request): Promise<Response> {
  return handle(async () => {
    requireSameOrigin(req);
    const user = await getCurrentUser();
    requireWriter(user);
    const tenantId = await requireTenant(user);
    const count = await withTenant(tenantId, async (tx) => {
      const r = await tx.endpoint.updateMany({ where: { tenantId }, data: { lastScanRequestedAt: null, lastScanAt: null } });
      await appendAudit(
        { tenantId, actor: user.upn, action: "endpoints.scan_requested", entity: "Endpoint", entityId: "*", payload: { count: r.count } },
        tx,
      );
      return r.count;
    });
    return ok({ queued: count });
  });
}
