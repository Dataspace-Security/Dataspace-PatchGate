import "server-only";
import { withTenant } from "@/lib/tenancy";
import type { AuthedConnector } from "./auth";
import { ConnectorApiError } from "./errors";

/**
 * GET /api/connector/v1/audit?after={seq}&limit=500 — the bank's OWN audit chain (never another bank's,
 * never the platform chain), oldest first, for the connector's SIEM relay. seq values are decimal
 * strings and strictly increasing; `head` lets the relay detect that it is behind. Each record carries its
 * prevHash so the bank SIEM can run the same chain-break / fork / regression rules as on PatchGate's export.
 */

export const MAX_AUDIT_PAGE = 500;
const SEQ_RE = /^\d{1,19}$/;
const MAX_SEQ = BigInt("9223372036854775807");

export interface AuditRelayPage {
  /** prevHash: the hash of the previous record of this bank's chain (as stored and hashed), for the SIEM chain-break rule. */
  records: { seq: string; ts: string; actor: string; action: string; entity: string; entityId: string; hash: string; prevHash: string | null; payload: unknown }[];
  head: { seq: string; hash: string } | null;
}

export function parseAuditQuery(url: URL): { after: bigint; limit: number } {
  const rawAfter = url.searchParams.get("after") ?? "0";
  const rawLimit = url.searchParams.get("limit") ?? String(MAX_AUDIT_PAGE);
  if (!SEQ_RE.test(rawAfter) || BigInt(rawAfter) > MAX_SEQ) throw new ConnectorApiError(400, "after must be a decimal sequence number");
  if (!/^\d{1,4}$/.test(rawLimit)) throw new ConnectorApiError(400, "limit must be 1-500");
  const limit = Math.max(1, Math.min(MAX_AUDIT_PAGE, Number(rawLimit)));
  return { after: BigInt(rawAfter), limit };
}

export async function auditPage(connector: AuthedConnector, after: bigint, limit: number): Promise<AuditRelayPage> {
  const tenantId = connector.tenantId;
  return withTenant(tenantId, async (tx) => {
    const rows = await tx.auditEvent.findMany({ where: { tenantId, seq: { gt: after } }, orderBy: { seq: "asc" }, take: limit });
    const head = await tx.auditEvent.findFirst({ where: { tenantId }, orderBy: { seq: "desc" }, select: { seq: true, hash: true } });
    return {
      records: rows.map((r) => ({
        seq: r.seq.toString(),
        ts: r.ts.toISOString(),
        actor: r.actor,
        action: r.action,
        entity: r.entity,
        entityId: r.entityId,
        hash: r.hash,
        prevHash: r.prevHash,
        payload: r.payload,
      })),
      head: head ? { seq: head.seq.toString(), hash: head.hash } : null,
    };
  });
}
