import "server-only";
import type { Prisma } from "@prisma/client";
import { appendAudit } from "@/lib/audit/service";
import { withTenant } from "@/lib/tenancy";
import type { AuthedConnector } from "./auth";
import { ConnectorApiError } from "./errors";
import { heartbeatSchema } from "./protocol";

/**
 * POST /api/connector/v1/heartbeat — the connector reports cache / Tactical / SIEM-relay health every
 * ~60 s and receives the bank's LAN limits. These limits can only LOWER the connector's local ceilings
 * (the connector takes min(local, PatchGate)). Version or cache-URL changes are audited.
 */

export interface HeartbeatReply {
  serverTime: string;
  maxConcurrentInstalls: number;
  bandwidthLimitMbps: number | null;
}

export async function recordHeartbeat(connector: AuthedConnector, body: unknown, now = new Date()): Promise<HeartbeatReply> {
  const parsed = heartbeatSchema.safeParse(body);
  if (!parsed.success) throw new ConnectorApiError(400, `invalid heartbeat: ${parsed.error.issues[0]?.message ?? "malformed"}`);
  const hb = parsed.data;
  return withTenant(connector.tenantId, async (tx) => {
    const before = await tx.connector.findUniqueOrThrow({
      where: { id: connector.id },
      select: { version: true, cacheBaseUrl: true, maxConcurrentInstalls: true, bandwidthLimitMbps: true },
    });
    const cacheBaseUrl = hb.cacheBaseUrl ?? null;
    await tx.connector.update({
      where: { id: connector.id },
      data: { lastSeenAt: now, version: hb.version, cacheBaseUrl, heartbeat: { ...hb, receivedAt: now.toISOString() } as Prisma.InputJsonValue },
    });
    if (before.version !== hb.version || before.cacheBaseUrl !== cacheBaseUrl) {
      await appendAudit(
        {
          tenantId: connector.tenantId,
          actor: `connector:${connector.id}`,
          action: "connector.reported_config",
          entity: "Connector",
          entityId: connector.id,
          payload: { version: { from: before.version, to: hb.version }, cacheBaseUrl: { from: before.cacheBaseUrl, to: cacheBaseUrl } },
        },
        tx,
      );
    }
    return { serverTime: now.toISOString(), maxConcurrentInstalls: before.maxConcurrentInstalls, bandwidthLimitMbps: before.bandwidthLimitMbps };
  });
}
