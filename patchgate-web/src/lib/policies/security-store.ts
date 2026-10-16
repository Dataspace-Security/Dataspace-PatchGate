import "server-only";
import type { Prisma } from "@prisma/client";
import { prisma } from "@/lib/db";
import { env } from "@/lib/env";
import { auditAuth } from "@/lib/auth/audit";
import { authTx } from "@/lib/auth/tx";
import type { SessionUser } from "@/lib/auth/session";
import { requirePlatformAdmin } from "@/lib/tenancy";
import { DEFAULT_SECURITY_POLICY, securityPolicySchema, type SecurityPolicyValues } from "./account-policy";

type Db = Prisma.TransactionClient | typeof prisma;

const POLICY_ID = "platform";

/** Current platform security policy (defaults when never saved). Works in any transaction scope. */
export async function getSecurityPolicy(db: Db = prisma): Promise<SecurityPolicyValues> {
  const row = await db.securityPolicy.findUnique({ where: { id: POLICY_ID } });
  if (!row) return { ...DEFAULT_SECURITY_POLICY };
  return { passwordMaxAgeDays: row.passwordMaxAgeDays, inactivityDisableDays: row.inactivityDisableDays, maxSessionsPerUser: row.maxSessionsPerUser };
}

export interface SecurityPolicyView extends SecurityPolicyValues {
  updatedAt: Date | null;
  updatedBy: string | null;
  /** Read-only, from the environment */
  sessionIdleMinutes: number;
  sessionMaxHours: number;
}

export async function securityPolicyView(): Promise<SecurityPolicyView> {
  const row = await prisma.securityPolicy.findUnique({ where: { id: POLICY_ID } });
  const e = env();
  return {
    ...(row ? { passwordMaxAgeDays: row.passwordMaxAgeDays, inactivityDisableDays: row.inactivityDisableDays, maxSessionsPerUser: row.maxSessionsPerUser } : DEFAULT_SECURITY_POLICY),
    updatedAt: row?.updatedAt ?? null,
    updatedBy: row?.updatedBy ?? null,
    sessionIdleMinutes: e.SESSION_IDLE_MINUTES,
    sessionMaxHours: e.SESSION_MAX_HOURS,
  };
}

/** Platform admins only. Audited on the platform chain with before/after values. */
export async function updateSecurityPolicy(actor: SessionUser, raw: unknown): Promise<SecurityPolicyValues> {
  requirePlatformAdmin(actor);
  const input = securityPolicySchema.parse(raw);
  return authTx(async (tx) => {
    // Serialise concurrent edits so the audited "from" values are exact.
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(4242031)`;
    const before = await getSecurityPolicy(tx);
    const after: SecurityPolicyValues = { ...before, ...input };
    await tx.securityPolicy.upsert({
      where: { id: POLICY_ID },
      create: { id: POLICY_ID, ...after, updatedBy: actor.upn },
      update: { ...after, updatedBy: actor.upn },
    });
    const changes = Object.fromEntries(
      (Object.keys(after) as (keyof SecurityPolicyValues)[]).filter((k) => after[k] !== before[k]).map((k) => [k, { from: before[k], to: after[k] }]),
    );
    await auditAuth({ actor: actor.upn, action: "security_policy.updated", entity: "SecurityPolicy", entityId: POLICY_ID, payload: { changes }, tenantId: null }, tx);
    return after;
  });
}
