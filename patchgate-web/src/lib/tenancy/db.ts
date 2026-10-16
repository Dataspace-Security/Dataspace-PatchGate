import "server-only";
import type { Prisma } from "@prisma/client";
import { prisma } from "@/lib/db";
import { isValidTenantId } from "./policy";

/**
 * Tenant-scoped database access (second isolation layer, PostgreSQL Row-Level Security).
 *
 * Every read/write of a bank's rows (Ring, MaintenanceWindow, Endpoint, EndpointPatchState, ChangeRequest,
 * ChangeRequestPatch, Deployment, InstalledSoftware, DiscoveredApp, TenantApp, and the bank's audit chain)
 * goes through one of these helpers. Inside the interactive transaction they:
 *  - set `app.scope` / `app.tenant_id` (transaction-local: they reset on COMMIT/ROLLBACK, so a pooled
 *    connection never carries a bank over to the next request), and
 *  - switch to the NOBYPASSRLS role `patchgate_tenant`, so the policies from migration
 *    20261015020000_rls apply even when the login role is a superuser or the table owner.
 * Queries still filter by tenantId explicitly (first layer); RLS catches the one that forgets.
 *
 * Keep network calls (Tactical, SIEM) OUT of the callback: the transaction holds a pooled connection.
 */

export type Tx = Prisma.TransactionClient;

/** Postgres role the helpers switch to (created by the RLS migration). */
export const RLS_ROLE = "patchgate_tenant";

export interface ScopeOptions {
  /** Interactive-transaction timeout (ms). Default 30 s; raise for bulk rebuilds. */
  timeoutMs?: number;
}

const MAX_WAIT_MS = 10_000;
const DEFAULT_TIMEOUT_MS = 30_000;

function txOptions(opts?: ScopeOptions) {
  return { maxWait: MAX_WAIT_MS, timeout: opts?.timeoutMs ?? DEFAULT_TIMEOUT_MS };
}

/** Run `fn` with visibility limited to ONE bank: other banks' rows are invisible and cannot be written. */
export async function withTenant<T>(tenantId: string, fn: (tx: Tx) => Promise<T>, opts?: ScopeOptions): Promise<T> {
  if (!isValidTenantId(tenantId)) throw new Error("withTenant: invalid tenant id");
  return prisma.$transaction(async (tx) => {
    await tx.$executeRaw`SELECT set_config('app.scope', 'tenant', true), set_config('app.tenant_id', ${tenantId}, true), set_config('role', ${RLS_ROLE}, true)`;
    return fn(tx);
  }, txOptions(opts));
}

/**
 * Run `fn` across ALL banks (platform workers, our staff's cross-bank views, per-bank audit export).
 * Still runs as the RLS role, so the scope is explicit and greppable — never the implicit default.
 */
export async function withPlatform<T>(fn: (tx: Tx) => Promise<T>, opts?: ScopeOptions): Promise<T> {
  return prisma.$transaction(async (tx) => {
    await tx.$executeRaw`SELECT set_config('app.scope', 'platform', true), set_config('app.tenant_id', '', true), set_config('role', ${RLS_ROLE}, true)`;
    return fn(tx);
  }, txOptions(opts));
}
