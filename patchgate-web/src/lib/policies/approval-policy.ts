import { z } from "zod";
import { EMERGENCY_APPROVALS } from "@/lib/approvals/state-machine";
import { isValidTimezone } from "./cron-preview";
import type { RebootPolicyValue } from "./reboot-labels";

/** Per-bank approval + change defaults (pure rules; persistence in bank-settings.ts). */

export { REBOOT_LABEL, REBOOT_POLICIES, type RebootPolicyValue } from "./reboot-labels";

export const MAX_APPROVAL_EXPIRY_DAYS = 365;
const DAY_MS = 86_400_000;

export const bankPolicySchema = z
  .object({
    // "Approval required" (default ON). OFF = an admin's request is approved on submit (no second person).
    requireBankApproval: z.boolean(),
    approvalExpiryDays: z.coerce.number().int().min(0).max(MAX_APPROVAL_EXPIRY_DAYS),
    maxTargetsPerCr: z.coerce.number().int().min(0).max(1_000_000),
    defaultRebootPolicy: z.enum(["NEVER", "REQUIRED", "ALWAYS"]),
    timezone: z.string().trim().min(1).max(64).refine(isValidTimezone, "unknown timezone"),
  })
  .partial()
  .refine((v) => Object.keys(v).length > 0, "nothing to change");
export type BankPolicyInput = z.infer<typeof bankPolicySchema>;

export interface BankPolicy {
  requireBankApproval: boolean;
  approvalExpiryDays: number;
  maxTargetsPerCr: number;
  defaultRebootPolicy: RebootPolicyValue;
  timezone: string;
}

/** Approvals a request needs when it is submitted: two for an emergency or above the bank's target limit. */
export function requiredApprovalsFor(input: { emergency: boolean; targetCount: number; maxTargetsPerCr: number }): number {
  if (input.emergency) return EMERGENCY_APPROVALS;
  if (input.maxTargetsPerCr > 0 && input.targetCount > input.maxTargetsPerCr) return 2;
  return 1;
}

/** When a final approval stops being valid (null = never). */
export function approvalExpiryFrom(approvedAt: Date, days: number): Date | null {
  if (!Number.isInteger(days) || days <= 0) return null;
  return new Date(approvedAt.getTime() + Math.min(days, MAX_APPROVAL_EXPIRY_DAYS) * DAY_MS);
}

/** Reboot policy for a new change request: explicit choice → ring override → bank default. */
export function resolveRebootPolicy(
  chosen: RebootPolicyValue | null | undefined,
  ringOverride: RebootPolicyValue | null | undefined,
  bankDefault: RebootPolicyValue,
): RebootPolicyValue {
  return chosen ?? ringOverride ?? bankDefault;
}
