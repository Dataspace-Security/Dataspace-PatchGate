import "server-only";
import { appendAudit } from "@/lib/audit/service";
import type { SessionUser } from "@/lib/auth/session";
import { DomainError } from "@/lib/errors";
import { withTenant, type Tx } from "@/lib/tenancy";
import { formatInTimezone, nextOccurrences, windowInputSchema, type WindowInput } from "./cron-preview";

/**
 * Maintenance windows of ONE bank (RLS-scoped, audited on the bank chain). A window belongs to one ring
 * (change requests may only use a window of their own ring). Safety:
 *  - the schedule (cron / duration / timezone) cannot change while a pending / approved / deploying request
 *    uses the window — the approver approved that schedule;
 *  - a window used by any request cannot move to another ring, nor be deleted (audit trail).
 */

const IN_FLIGHT = ["PENDING_APPROVAL", "APPROVED", "DEPLOYING"] as const;

export async function listWindows(tenantId: string) {
  return withTenant(tenantId, (tx) =>
    tx.maintenanceWindow.findMany({
      where: { tenantId },
      orderBy: [{ ring: { order: "asc" } }, { name: "asc" }],
      include: { ring: { select: { id: true, name: true } }, _count: { select: { changeRequests: true } } },
    }),
  );
}

export interface OccurrencePreview {
  start: string;
  end: string;
  startLocal: string;
  endLocal: string;
}

/** Next occurrences of a (validated) window spec, formatted in the bank's timezone. */
export function previewWindow(spec: Pick<WindowInput, "cron" | "durationMin" | "timezone">, bankTimezone: string, now = new Date()): OccurrencePreview[] {
  return nextOccurrences(spec, now).map((o) => ({
    start: o.start.toISOString(),
    end: o.end.toISOString(),
    startLocal: formatInTimezone(o.start, bankTimezone),
    endLocal: formatInTimezone(o.end, bankTimezone),
  }));
}

async function assertRing(tx: Tx, tenantId: string, ringId: string): Promise<void> {
  if (!(await tx.ring.findFirst({ where: { id: ringId, tenantId }, select: { id: true } }))) throw new DomainError("Ring not found", 404);
}

export async function createWindow(user: SessionUser, tenantId: string, raw: unknown) {
  const input = windowInputSchema.parse(raw);
  return withTenant(tenantId, async (tx) => {
    await assertRing(tx, tenantId, input.ringId);
    const w = await tx.maintenanceWindow.create({ data: { tenantId, ...input } });
    await appendAudit({ tenantId, actor: user.upn, action: "window.created", entity: "MaintenanceWindow", entityId: w.id, payload: { ...input } }, tx);
    return w;
  });
}

export async function updateWindow(user: SessionUser, tenantId: string, windowId: string, raw: unknown) {
  const input = windowInputSchema.parse(raw);
  return withTenant(tenantId, async (tx) => {
    const before = await tx.maintenanceWindow.findFirst({ where: { id: windowId, tenantId } });
    if (!before) throw new DomainError("Maintenance window not found", 404);
    await assertRing(tx, tenantId, input.ringId);
    const scheduleChanged = before.cron !== input.cron || before.durationMin !== input.durationMin || before.timezone !== input.timezone;
    if (scheduleChanged && (await tx.changeRequest.count({ where: { tenantId, windowId, status: { in: [...IN_FLIGHT] } } })) > 0) {
      throw new DomainError("A pending, approved or deploying change request uses this window; its schedule cannot change", 409);
    }
    if (before.ringId !== input.ringId && (await tx.changeRequest.count({ where: { tenantId, windowId } })) > 0) {
      throw new DomainError("Change requests use this window; it cannot move to another ring (create a new window instead)", 409);
    }
    await tx.maintenanceWindow.updateMany({ where: { id: windowId, tenantId }, data: { ...input } });
    const changes = Object.fromEntries(
      (Object.keys(input) as (keyof WindowInput)[]).filter((k) => before[k] !== input[k]).map((k) => [k, { from: before[k], to: input[k] }]),
    );
    await appendAudit({ tenantId, actor: user.upn, action: "window.updated", entity: "MaintenanceWindow", entityId: windowId, payload: { changes } }, tx);
    return { ...before, ...input };
  });
}

export async function deleteWindow(user: SessionUser, tenantId: string, windowId: string) {
  return withTenant(tenantId, async (tx) => {
    const w = await tx.maintenanceWindow.findFirst({ where: { id: windowId, tenantId }, include: { _count: { select: { changeRequests: true } } } });
    if (!w) throw new DomainError("Maintenance window not found", 404);
    if (w._count.changeRequests > 0) throw new DomainError("Change requests use this window (kept for the audit trail); it cannot be deleted", 409);
    await tx.maintenanceWindow.deleteMany({ where: { id: windowId, tenantId } });
    await appendAudit(
      { tenantId, actor: user.upn, action: "window.deleted", entity: "MaintenanceWindow", entityId: windowId, payload: { name: w.name, ringId: w.ringId, cron: w.cron } },
      tx,
    );
    return { id: windowId };
  });
}
