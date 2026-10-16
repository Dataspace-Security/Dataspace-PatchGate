import type { TacticalWinUpdate } from "./types.ts";

/**
 * Copied from patchgate-web/src/lib/tactical/deploy-plan.ts.
 * Tactical's POST /winupdate/{agent}/install/ re-approves by patch policy and then installs EVERY
 * update whose action is "approve". So before installing, Tactical's approval state must exactly
 * mirror the job's GUID set: approve ours, reset everything else, then re-read and verify.
 */

export const normGuid = (g: string): string => g.toLowerCase();

export interface DeployPlan {
  /** Tactical WinUpdate pks to set action=approve */
  toApprove: number[];
  /** Tactical WinUpdate pks to set action=nothing (stale approve / inherit) */
  toReset: number[];
  /** GUIDs that will actually be installed */
  installTargets: string[];
  /** Requested GUIDs Tactical hasn't seen on this agent (needs a SCAN, or not applicable) */
  missingOnAgent: string[];
}

export function buildDeployPlan(agentUpdates: readonly TacticalWinUpdate[], approvedGuids: ReadonlySet<string>): DeployPlan {
  const approved = new Set([...approvedGuids].map(normGuid));
  const toApprove: number[] = [];
  const toReset: number[] = [];
  const installTargets: string[] = [];
  const seen = new Set<string>();

  for (const u of agentUpdates) {
    const g = normGuid(u.guid);
    seen.add(g);
    const wanted = approved.has(g) && !u.installed;
    if (wanted) {
      installTargets.push(g);
      if (u.action !== "approve") toApprove.push(u.id);
    } else if (!u.installed && (u.action === "approve" || u.action === "inherit")) {
      toReset.push(u.id);
    }
  }

  const missingOnAgent = [...approved].filter((g) => !seen.has(g));
  return { toApprove, toReset, installTargets, missingOnAgent };
}

export type ApprovalCheck = { ok: true } | { ok: false; unexpected: string[]; missing: string[] };

/** Install may only proceed if Tactical's pending-approved set equals our targets exactly. */
export function checkApprovalState(agentUpdates: readonly TacticalWinUpdate[], installTargets: readonly string[]): ApprovalCheck {
  const approved = new Set(agentUpdates.filter((u) => !u.installed && u.action === "approve").map((u) => normGuid(u.guid)));
  const targets = new Set(installTargets.map(normGuid));
  const unexpected = [...approved].filter((g) => !targets.has(g));
  const missing = [...targets].filter((g) => !approved.has(g));
  return unexpected.length === 0 && missing.length === 0 ? { ok: true } : { ok: false, unexpected, missing };
}
