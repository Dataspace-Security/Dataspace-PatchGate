import "server-only";
import type { Prisma } from "@prisma/client";
import { prisma } from "@/lib/db";

/**
 * Interactive transactions for sign-in / account administration. Prisma's default (5 s timeout, 2 s wait)
 * is too tight when a worker tick holds the audit-chain advisory lock or the host is busy: users then saw
 * "Sign-in is temporarily unavailable" (P2028). These transactions are tiny; waiting is the right behaviour.
 */
export const AUTH_TX_OPTIONS = { timeout: 20_000, maxWait: 10_000 } as const;

export function authTx<T>(fn: (tx: Prisma.TransactionClient) => Promise<T>): Promise<T> {
  return prisma.$transaction(fn, AUTH_TX_OPTIONS);
}
