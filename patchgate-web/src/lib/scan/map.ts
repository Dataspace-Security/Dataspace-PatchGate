import { compareVersions, type InventoryItem } from "@/lib/thirdparty/version";

export type Severity = "CRITICAL" | "IMPORTANT" | "MODERATE" | "LOW" | "UNSPECIFIED";

const SEVERITIES: Record<string, Severity> = {
  critical: "CRITICAL",
  important: "IMPORTANT",
  moderate: "MODERATE",
  low: "LOW",
};

/** Tactical reports MSRC severity strings ("Critical", "Important", ... or empty). */
export function mapSeverity(s: string | null | undefined): Severity {
  return SEVERITIES[(s ?? "").trim().toLowerCase()] ?? "UNSPECIFIED";
}

/** Compliance status of a managed third-party app on one PC; null = app not installed there. */
export function thirdPartyStatus(
  inventory: readonly InventoryItem[],
  inventoryMatch: string,
  approvedVersion: string,
): "NEEDED" | "INSTALLED" | null {
  let re: RegExp;
  try {
    re = new RegExp(inventoryMatch, "i");
  } catch {
    return null;
  }
  const matches = inventory.filter((i) => re.test(i.name));
  if (matches.length === 0) return null;
  // Multiple installs (e.g. x86 + x64): compliant only if every copy is current.
  return matches.every((m) => compareVersions(m.version, approvedVersion) >= 0) ? "INSTALLED" : "NEEDED";
}
