import { packageInputSchema } from "@/lib/thirdparty/package-input";
import {
  agentReleaseToPackage,
  appVersionToPackage,
  hasAllAgentArches,
  type AgentReleaseRow,
  type AppVersionRow,
} from "@/lib/thirdparty/package-from-db";

/** Minimal patch shape needed to decide if it may be approved / deployed. */
export interface EligiblePatch {
  title: string;
  kind: "WINDOWS" | "THIRD_PARTY" | "AGENT_UPGRADE";
  supersededById: string | null;
  appVersion:
    | (AppVersionRow & {
        verification: "PENDING" | "HELD" | "VERIFIED" | "REJECTED";
        availableAt: Date | null;
      })
    | null;
  /** AGENT_UPGRADE only: VERIFIED mirrored builds for this version (any arch) */
  agentReleases?: readonly AgentReleaseRow[];
  /** THIRD_PARTY only: has the target bank opted in to this app (TenantApp)? undefined = not checked */
  tenantAppEnabled?: boolean;
}

/** Checked at create, and again at deploy. Empty array = eligible. */
export function eligibilityErrors(patches: readonly EligiblePatch[], now: Date): string[] {
  const errors: string[] = [];
  for (const p of patches) {
    if (p.supersededById) {
      errors.push(`${p.title}: superseded by a newer patch`);
      continue;
    }

    if (p.kind === "AGENT_UPGRADE") {
      const rel = p.agentReleases ?? [];
      if (rel.length === 0) errors.push(`${p.title}: no approved agent build in the mirror`);
      else if (!hasAllAgentArches(rel)) errors.push(`${p.title}: approve both amd64 and 386 agent builds first`);
      else if (!rel.every((r) => packageInputSchema.safeParse(agentReleaseToPackage(r)).success)) {
        errors.push(`${p.title}: invalid agent build metadata`);
      }
      continue;
    }
    if (p.kind !== "THIRD_PARTY") continue;

    const v = p.appVersion;
    if (!v) {
      errors.push(`${p.title}: no package attached`);
      continue;
    }
    if (p.tenantAppEnabled === false) {
      errors.push(`${p.title}: app not enabled for this bank`);
      continue;
    }
    if (v.verification !== "VERIFIED") errors.push(`${p.title}: package not verified`);
    else if (!v.repoPath) errors.push(`${p.title}: package not published to repo`);
    else if (!v.availableAt || v.availableAt > now) errors.push(`${p.title}: still in quarantine`);
    else if (!packageInputSchema.safeParse(appVersionToPackage(v)).success) {
      errors.push(`${p.title}: invalid package metadata`);
    }
  }
  return errors;
}
