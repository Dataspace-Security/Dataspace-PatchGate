import type { TacticalWinUpdate } from "./types";

/** WSUS and agents may report the same UpdateID in different case. */
export const normGuid = (g: string): string => g.toLowerCase();

/**
 * Tactical's POST /winupdate/{agent}/install/ installs EVERY update whose action is
 * "approve" on that agent. So before installing we must make Tactical's approval state
 * exactly mirror PatchGate's approved set: approve ours, reset everything else.
 */
export interface DeployPlan {
  /** Tactical WinUpdate pks to set action=approve */
  toApprove: number[];
  /** Tactical WinUpdate pks to set action=nothing (stale approve / inherit) */
  toReset: number[];
  /** GUIDs that will actually be installed */
  installTargets: string[];
  /** Approved GUIDs Tactical hasn't seen on this agent — trigger a rescan */
  missingOnAgent: string[];
}

export function buildDeployPlan(
  agentUpdates: readonly TacticalWinUpdate[],
  approvedGuids: ReadonlySet<string>,
): DeployPlan {
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

export type ApprovalCheck =
  | { ok: true }
  | { ok: false; unexpected: string[]; missing: string[] };

/**
 * Re-read after applying the plan: Tactical may re-approve by its own patch policy.
 * Install must only proceed if Tactical's pending-approved set equals our targets exactly.
 */
export function checkApprovalState(
  agentUpdates: readonly TacticalWinUpdate[],
  installTargets: readonly string[],
): ApprovalCheck {
  const approved = new Set(
    agentUpdates.filter((u) => !u.installed && u.action === "approve").map((u) => normGuid(u.guid)),
  );
  const targets = new Set(installTargets.map(normGuid));
  const unexpected = [...approved].filter((g) => !targets.has(g));
  const missing = [...targets].filter((g) => !approved.has(g));
  return unexpected.length === 0 && missing.length === 0 ? { ok: true } : { ok: false, unexpected, missing };
}

/** Done only when every GUID is reported by the agent AND installed. Unknown ≠ installed. */
export function windowsInstallComplete(
  agentUpdates: readonly TacticalWinUpdate[],
  guids: readonly string[],
): boolean {
  const byGuid = new Map(agentUpdates.map((u) => [normGuid(u.guid), u]));
  return guids.every((g) => byGuid.get(normGuid(g))?.installed === true);
}
