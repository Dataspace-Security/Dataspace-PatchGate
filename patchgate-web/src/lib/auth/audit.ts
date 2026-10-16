import "server-only";
import type { Prisma } from "@prisma/client";
import { appendAudit, type AuditInput } from "@/lib/audit/service";

type Tx = Prisma.TransactionClient;

export interface AuthAuditEvent extends AuditInput {
  /** Audit chain owner: the bank of the user concerned, or null for the platform chain. */
  tenantId: string | null;
}

/**
 * Audit an authentication / user-administration event on the right chain.
 * Typed loosely on purpose so it compiles whether or not AuditInput already declares `tenantId`.
 */
export async function auditAuth(event: AuthAuditEvent, tx?: Tx): Promise<void> {
  const input: AuditInput = event;
  await appendAudit(input, tx);
}
