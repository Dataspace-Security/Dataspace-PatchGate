import { TacticalError, type TacticalClient } from "@/lib/tactical/client";
import { buildDeployPlan, checkApprovalState } from "@/lib/tactical/deploy-plan";
import { parseInstallResult, toInstallEnv, type PackageInput } from "@/lib/thirdparty/package-input";
import { compareVersions } from "@/lib/thirdparty/version";

/** How many scan rounds to wait for an approved GUID to appear on the agent. */
export const MAX_SCAN_ROUNDS = 3;
const THIRD_PARTY_SCRIPT_TIMEOUT_SEC = 900;

export interface PushInput {
  agentId: string;
  /** Number of attempts already made, including this one */
  attempt: number;
  windowsGuids: ReadonlySet<string>;
  packages: readonly PackageInput[];
  repoUrl: string;
  installScriptId: number | undefined;
}

export type PushOutcome =
  | { kind: "sent"; targetGuids: string[]; note: string | null }
  | { kind: "retry"; reason: string };

/**
 * Push one endpoint's share of a change request through Tactical.
 * Throws on hard failure (caller marks the deployment FAILED).
 */
export async function pushToEndpoint(tactical: TacticalClient, input: PushInput): Promise<PushOutcome> {
  let targetGuids: string[] = [];
  let note: string | null = null;

  if (input.windowsGuids.size > 0) {
    const plan = buildDeployPlan(await tactical.getUpdates(input.agentId), input.windowsGuids);

    if (plan.missingOnAgent.length > 0) {
      if (input.attempt < MAX_SCAN_ROUNDS) {
        await tactical.scanUpdates(input.agentId);
        return { kind: "retry", reason: `waiting for agent scan (${plan.missingOnAgent.length} not visible)` };
      }
      // After several scans the agent still doesn't offer them: not applicable to this PC.
      note = `Not offered by Windows Update on this PC (likely not applicable): ${plan.missingOnAgent.join(", ")}`;
    }

    // Reset first so Tactical never holds a foreign approval when install fires.
    for (const pk of plan.toReset) await tactical.setUpdateAction(pk, "nothing");
    for (const pk of plan.toApprove) await tactical.setUpdateAction(pk, "approve");

    if (plan.installTargets.length > 0) {
      const after = await tactical.getUpdates(input.agentId);
      const check = checkApprovalState(after, plan.installTargets);
      if (!check.ok) {
        // Fail safe: withdraw our approvals and refuse to install.
        for (const pk of plan.toApprove) await tactical.setUpdateAction(pk, "nothing");
        throw new Error(
          `Tactical approval state mismatch (unexpected: ${check.unexpected.join(",") || "-"}; ` +
            `missing: ${check.missing.join(",") || "-"}). Ensure Tactical patch policy severities are 'manual'.`,
        );
      }
      await tactical.installApproved(input.agentId);
    }
    targetGuids = plan.installTargets;
  }

  if (input.packages.length > 0) {
    if (!input.installScriptId) throw new Error("TACTICAL_INSTALL_SCRIPT_ID not configured");
    // The agent upgrade restarts the Tactical agent itself, so it always runs last.
    const ordered = [...input.packages.filter((p) => p.kind !== "agent"), ...input.packages.filter((p) => p.kind === "agent")];
    for (const pkg of ordered) {
      if (pkg.kind === "agent") {
        const current = await tactical.getAgent(input.agentId);
        if (compareVersions(current.version, pkg.version) >= 0) {
          const msg = `agent already at ${current.version} (target ${pkg.version})`;
          note = note ? `${note}; ${msg}` : msg;
          continue;
        }
      }
      let out: string;
      try {
        out = await tactical.runScript(input.agentId, {
          scriptId: input.installScriptId,
          timeoutSec: THIRD_PARTY_SCRIPT_TIMEOUT_SEC,
          envVars: toInstallEnv(pkg, input.repoUrl),
        });
      } catch (err: unknown) {
        // No HTTP status = the request may already be running on the PC. Retrying could start a
        // second installer, so treat the outcome as unknown and let reconcile confirm via inventory.
        if (err instanceof TacticalError && err.status === undefined) {
          const msg = `${pkg.wingetId} ${pkg.version}: install result unknown (${err.message}); confirming via inventory`;
          note = note ? `${note}; ${msg}` : msg;
          continue;
        }
        throw err;
      }
      const result = parseInstallResult(out);
      if (!result.ok) throw new Error(`${pkg.wingetId} ${pkg.version}: ${result.reason}`);
    }
    if (ordered.some((p) => p.kind !== "agent")) await tactical.refreshSoftware(input.agentId);
  }

  return { kind: "sent", targetGuids, note };
}
