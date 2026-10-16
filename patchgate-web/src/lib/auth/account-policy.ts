import { z } from "zod";
import { checkPasswordPolicy, PASSWORD_MAX, type PolicyResult } from "./password";

/** Pure rules for the self-service password change (/account). Hash comparisons happen in account-service. */

export const changeOwnPasswordSchema = z.object({
  currentPassword: z.string().min(1, "enter your current password").max(1024),
  newPassword: z.string().min(1, "enter a new password").max(PASSWORD_MAX * 4),
  confirmPassword: z.string().max(PASSWORD_MAX * 4),
});
export type ChangeOwnPasswordInput = z.infer<typeof changeOwnPasswordSchema>;

export const CONFIRM_MISMATCH = "The new password and its confirmation do not match.";
export const SAME_PASSWORD = "Choose a password different from your current one.";

/** Confirmation, password policy and "not the same as the current one" (plain-text check). */
export function checkNewPassword(input: ChangeOwnPasswordInput, upn: string): PolicyResult {
  if (input.newPassword !== input.confirmPassword) return { ok: false, reason: CONFIRM_MISMATCH };
  if (input.newPassword === input.currentPassword) return { ok: false, reason: SAME_PASSWORD };
  return checkPasswordPolicy(input.newPassword, upn);
}
