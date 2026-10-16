import { Prisma } from "@prisma/client";
import { getCurrentUser, requireSameOrigin, requireWriter } from "@/lib/auth/session";
import { handle, ok } from "@/lib/api/response";
import { appendAudit } from "@/lib/audit/service";
import { tenantUsesConnector } from "@/lib/connector/routing";
import { DomainError } from "@/lib/errors";
import { requestConnectorAgentSync } from "@/lib/scan/scan-request";
import { agentTimes } from "@/lib/tactical/agent-times";
import { tacticalForTenant } from "@/lib/tactical/from-env";
import { requireTenant, withTenant } from "@/lib/tenancy";

const SYNC_TX_TIMEOUT_MS = 120_000;

/**
 * Pull the Windows agent list from Tactical into PatchGate (ADMIN only, audited).
 * Connector banks: a SYNC_AGENTS job for the site connector(s) right away (de-duplicated; the result arrives
 * asynchronously). The legacy bank on the direct Tactical link: read synchronously.
 */
export async function POST(req: Request): Promise<Response> {
  return handle(async () => {
    requireSameOrigin(req);
    const user = await getCurrentUser();
    requireWriter(user);
    const tenantId = await requireTenant(user);
    if (await tenantUsesConnector(tenantId)) return ok(await requestConnectorAgentSync(tenantId, user.upn));
    const tactical = tacticalForTenant(tenantId);

    // Network first, then one bank-scoped transaction.
    const agents = (await tactical.listAgents()).filter((a) => a.plat === "windows");
    try {
      await withTenant(
        tenantId,
        async (tx) => {
          const now = new Date();
          for (const a of agents) {
            const times = agentTimes({ lastSeen: a.last_seen, bootTime: a.boot_time, online: a.status ? a.status === "online" : null }, now);
            const data = {
              hostname: a.hostname,
              client: a.client_name ?? null,
              site: a.site_name ?? null,
              osName: a.operating_system ?? null,
              agentVersion: a.version ?? null,
              goarch: a.goarch ?? null,
              // Tactical last_seen / boot_time in UTC, clock skew guarded (null last seen = keep the previous value)
              ...(times.lastSeenAt ? { lastSeenAt: times.lastSeenAt } : {}),
              bootedAt: times.bootedAt,
            };
            // Agent ids are globally unique. Other banks' rows are invisible here (RLS), so an id that
            // belongs to another bank fails on the unique index instead of moving that PC.
            const existing = await tx.endpoint.findFirst({ where: { tacticalAgentId: a.agent_id, tenantId }, select: { id: true } });
            if (existing) await tx.endpoint.update({ where: { id: existing.id }, data });
            else await tx.endpoint.create({ data: { tenantId, tacticalAgentId: a.agent_id, ...data } });
          }
          await appendAudit(
            { tenantId, actor: user.upn, action: "endpoints.sync", entity: "Endpoint", entityId: "*", payload: { count: agents.length } },
            tx,
          );
        },
        { timeoutMs: SYNC_TX_TIMEOUT_MS },
      );
    } catch (err: unknown) {
      if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === "P2002") {
        throw new DomainError("A Tactical agent is already registered to another bank", 409);
      }
      throw err;
    }
    return ok({ synced: agents.length });
  });
}
