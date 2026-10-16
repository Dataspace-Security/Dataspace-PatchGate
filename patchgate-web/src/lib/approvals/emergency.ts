import "server-only";
import { z } from "zod";
import { appendAudit } from "@/lib/audit/service";
import type { SessionUser } from "@/lib/auth/session";
import { DomainError } from "@/lib/errors";
import { withTenant } from "@/lib/tenancy";
import { assertCanActFor } from "./service";

/**
 * Draft options set by the maker before submitting: EMERGENCY (reason required → two distinct approvers,
 * optional window bypass) and the reboot policy. Only the creator, only while DRAFT; audited on the bank
 * chain (change_request.emergency_marked / emergency_cleared / options_updated).
 */

export const draftOptionsSchema = z
  .object({
    emergency: z.boolean().optional(),
    emergencyReason: z.string().trim().max(500).nullish(),
    rebootPolicy: z.enum(["NEVER", "REQUIRED", "ALWAYS"]).optional(),
  })
  .refine((v) => v.emergency !== undefined || v.rebootPolicy !== undefined, "nothing to change")
  .refine((v) => v.emergency !== true || (v.emergencyReason ?? "").length >= 10, {
    path: ["emergencyReason"],
    message: "describe the emergency (at least 10 characters)",
  });
export type DraftOptionsInput = z.infer<typeof draftOptionsSchema>;

export async function updateDraftOptions(user: SessionUser, tenantId: string, crId: string, raw: unknown) {
  assertCanActFor(user, tenantId);
  const input = draftOptionsSchema.parse(raw);
  return withTenant(tenantId, async (tx) => {
    const cr = await tx.changeRequest.findFirst({
      where: { id: crId, tenantId },
      select: { status: true, createdById: true, emergency: true, emergencyReason: true, rebootPolicy: true },
    });
    if (!cr) throw new DomainError("Change request not found", 404);
    if (cr.status !== "DRAFT") throw new DomainError("Options can only be changed while the request is a draft", 409);
    if (cr.createdById !== user.id) throw new DomainError("Only the creator (maker) can change the draft options", 409);

    const emergency = input.emergency ?? cr.emergency;
    const emergencyReason = input.emergency === undefined ? cr.emergencyReason : emergency ? (input.emergencyReason ?? null) : null;
    const rebootPolicy = input.rebootPolicy ?? cr.rebootPolicy;
    const { count } = await tx.changeRequest.updateMany({
      where: { id: crId, tenantId, status: "DRAFT" },
      data: { emergency, emergencyReason, rebootPolicy, requiredApprovals: emergency ? 2 : 1 },
    });
    if (count !== 1) throw new DomainError("Change request was modified concurrently", 409);

    const base = { tenantId, actor: user.upn, entity: "ChangeRequest", entityId: crId };
    if (emergency && (!cr.emergency || emergencyReason !== cr.emergencyReason)) {
      await appendAudit({ ...base, action: "change_request.emergency_marked", payload: { reason: emergencyReason } }, tx);
    } else if (!emergency && cr.emergency) {
      await appendAudit({ ...base, action: "change_request.emergency_cleared", payload: { previousReason: cr.emergencyReason } }, tx);
    }
    if (rebootPolicy !== cr.rebootPolicy) {
      await appendAudit({ ...base, action: "change_request.options_updated", payload: { rebootPolicy: { from: cr.rebootPolicy, to: rebootPolicy } } }, tx);
    }
    return { id: crId, emergency, emergencyReason, rebootPolicy };
  });
}
