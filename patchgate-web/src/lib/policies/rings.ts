import "server-only";
import { Prisma } from "@prisma/client";
import { z } from "zod";
import { appendAudit } from "@/lib/audit/service";
import type { SessionUser } from "@/lib/auth/session";
import { DomainError } from "@/lib/errors";
import { withTenant, type Tx } from "@/lib/tenancy";

/**
 * Rollout rings of ONE bank (RLS-scoped, audited on the bank chain). wsusGroup follows the ring name unless
 * the bank set its own WSUS group name; it cannot change while a request for the ring is in flight (WSUS
 * approvals are keyed by group). Delete only an empty ring: no endpoints and no change requests.
 */

const ringName = z
  .string()
  .trim()
  .min(2)
  .max(64)
  .regex(/^[A-Za-z0-9][A-Za-z0-9 ._-]*$/, "letters, digits, space, dot, dash or underscore");
const rebootPolicy = z.enum(["NEVER", "REQUIRED", "ALWAYS"]);

export const createRingSchema = z.object({ name: ringName, wsusGroup: ringName.optional(), rebootPolicy: rebootPolicy.nullish() });
export const updateRingSchema = z
  .object({ name: ringName, wsusGroup: ringName, rebootPolicy: rebootPolicy.nullable() })
  .partial()
  .refine((v) => Object.keys(v).length > 0, "nothing to change");
export const reorderRingsSchema = z.object({ ringIds: z.array(z.string().min(1).max(64)).min(1).max(100) });

const IN_FLIGHT = ["PENDING_APPROVAL", "APPROVED", "DEPLOYING"] as const;

function uniqueViolation(err: unknown): never {
  if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === "P2002") {
    throw new DomainError("Another ring of this bank already uses that name or WSUS group", 409);
  }
  throw err;
}

export async function listRings(tenantId: string) {
  return withTenant(tenantId, (tx) =>
    tx.ring.findMany({
      where: { tenantId },
      orderBy: { order: "asc" },
      include: { _count: { select: { endpoints: true, changeRequests: true, windows: true } } },
    }),
  );
}

async function audit(tx: Tx, tenantId: string, user: SessionUser, action: string, entityId: string, payload: Prisma.InputJsonValue) {
  await appendAudit({ tenantId, actor: user.upn, action, entity: "Ring", entityId, payload }, tx);
}

export async function createRing(user: SessionUser, tenantId: string, raw: unknown) {
  const input = createRingSchema.parse(raw);
  return withTenant(tenantId, async (tx) => {
    const last = await tx.ring.findFirst({ where: { tenantId }, orderBy: { order: "desc" }, select: { order: true } });
    const ring = await tx.ring
      .create({ data: { tenantId, name: input.name, wsusGroup: input.wsusGroup ?? input.name, order: (last?.order ?? -1) + 1, rebootPolicy: input.rebootPolicy ?? null } })
      .catch(uniqueViolation);
    await audit(tx, tenantId, user, "ring.created", ring.id, { name: ring.name, wsusGroup: ring.wsusGroup, order: ring.order, rebootPolicy: ring.rebootPolicy });
    return ring;
  });
}

export async function updateRing(user: SessionUser, tenantId: string, ringId: string, raw: unknown) {
  const input = updateRingSchema.parse(raw);
  return withTenant(tenantId, async (tx) => {
    const before = await tx.ring.findFirst({ where: { id: ringId, tenantId } });
    if (!before) throw new DomainError("Ring not found", 404);
    const name = input.name ?? before.name;
    // Default WSUS group = ring name: keep them in step on rename unless the bank chose its own group.
    const wsusGroup = input.wsusGroup ?? (before.wsusGroup === before.name ? name : before.wsusGroup);
    if (wsusGroup !== before.wsusGroup) {
      const busy = await tx.changeRequest.count({ where: { tenantId, ringId, status: { in: [...IN_FLIGHT] } } });
      if (busy > 0) throw new DomainError("The WSUS group cannot change while a change request for this ring is pending, approved or deploying", 409);
    }
    const rebootPolicy = input.rebootPolicy === undefined ? before.rebootPolicy : input.rebootPolicy;
    await tx.ring.updateMany({ where: { id: ringId, tenantId }, data: { name, wsusGroup, rebootPolicy } }).catch(uniqueViolation);
    const changes = Object.fromEntries(
      (["name", "wsusGroup", "rebootPolicy"] as const)
        .filter((k) => ({ name, wsusGroup, rebootPolicy })[k] !== before[k])
        .map((k) => [k, { from: before[k], to: ({ name, wsusGroup, rebootPolicy })[k] }]),
    );
    await audit(tx, tenantId, user, "ring.updated", ringId, { changes });
    return { ...before, name, wsusGroup, rebootPolicy };
  });
}

/** New rollout order (must list every ring of the bank exactly once). Two phases: `order` is unique per bank. */
export async function reorderRings(user: SessionUser, tenantId: string, raw: unknown) {
  const { ringIds } = reorderRingsSchema.parse(raw);
  return withTenant(tenantId, async (tx) => {
    const rings = await tx.ring.findMany({ where: { tenantId }, select: { id: true, name: true, order: true }, orderBy: { order: "asc" } });
    const known = new Set(rings.map((r) => r.id));
    if (ringIds.length !== rings.length || new Set(ringIds).size !== ringIds.length || !ringIds.every((id) => known.has(id))) {
      throw new DomainError("List every ring of this bank exactly once", 400);
    }
    for (const [i, id] of ringIds.entries()) await tx.ring.updateMany({ where: { id, tenantId }, data: { order: -(i + 1) } });
    for (const [i, id] of ringIds.entries()) await tx.ring.updateMany({ where: { id, tenantId }, data: { order: i } });
    const name = new Map(rings.map((r) => [r.id, r.name]));
    await audit(tx, tenantId, user, "ring.reordered", tenantId, { from: rings.map((r) => r.name), to: ringIds.map((id) => name.get(id) ?? id) });
    return ringIds;
  });
}

/** Delete an EMPTY ring (no endpoints, no change requests); its maintenance windows go with it. */
export async function deleteRing(user: SessionUser, tenantId: string, ringId: string) {
  return withTenant(tenantId, async (tx) => {
    const ring = await tx.ring.findFirst({ where: { id: ringId, tenantId }, include: { _count: { select: { endpoints: true, changeRequests: true } } } });
    if (!ring) throw new DomainError("Ring not found", 404);
    if (ring._count.endpoints > 0) throw new DomainError(`Move the ${ring._count.endpoints} endpoint(s) out of this ring first`, 409);
    if (ring._count.changeRequests > 0) throw new DomainError("This ring has change requests (kept for the audit trail) and cannot be deleted", 409);
    const windows = await tx.maintenanceWindow.findMany({ where: { tenantId, ringId }, select: { id: true, name: true } });
    await tx.maintenanceWindow.deleteMany({ where: { tenantId, ringId } });
    await tx.ring.deleteMany({ where: { id: ringId, tenantId } });
    await audit(tx, tenantId, user, "ring.deleted", ringId, { name: ring.name, wsusGroup: ring.wsusGroup, windowsDeleted: windows.map((w) => w.name) });
    return { id: ringId };
  });
}
