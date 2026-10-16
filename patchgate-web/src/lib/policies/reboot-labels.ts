/** Reboot policy values + UI labels (no dependencies: safe for client components). */

export type RebootPolicyValue = "NEVER" | "REQUIRED" | "ALWAYS";
export const REBOOT_POLICIES: readonly RebootPolicyValue[] = ["NEVER", "REQUIRED", "ALWAYS"];

/** REQUIRED = reboot only if an update needs it (IF_REQUIRED); ALWAYS = force a reboot (FORCE). */
export const REBOOT_LABEL: Record<RebootPolicyValue, string> = {
  NEVER: "Never reboot",
  REQUIRED: "Reboot if required",
  ALWAYS: "Force reboot",
};
