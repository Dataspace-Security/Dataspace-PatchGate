import "server-only";
import { withPlatform, withTenant } from "@/lib/tenancy";
import { isOnline } from "./policy";

/**
 * Which path reaches a bank's PCs:
 *  - a bank with at least one ACTIVE connector → the signed job pipeline (src/lib/connector/**);
 *  - otherwise, only the legacy bank (LEGACY_TACTICAL_TENANT_ID) → the direct Tactical link (src/lib/deploy/worker.ts).
 */

export async function tenantUsesConnector(tenantId: string): Promise<boolean> {
  const n = await withTenant(tenantId, (tx) => tx.connector.count({ where: { tenantId, status: "ACTIVE" } }));
  return n > 0;
}

export interface ActiveConnector {
  id: string;
  tenantId: string;
  name: string;
  maxConcurrentInstalls: number;
  lastSeenAt: Date | null;
  online: boolean;
}

/** Every ACTIVE connector of every active bank (worker steps iterate these). */
export async function activeConnectors(now = new Date()): Promise<ActiveConnector[]> {
  const rows = await withPlatform((tx) =>
    tx.connector.findMany({
      where: { status: "ACTIVE", tenant: { active: true } },
      orderBy: [{ tenantId: "asc" }, { name: "asc" }],
      select: { id: true, tenantId: true, name: true, maxConcurrentInstalls: true, lastSeenAt: true },
    }),
  );
  return rows.map((r) => ({ ...r, online: isOnline(r.lastSeenAt, now) }));
}
