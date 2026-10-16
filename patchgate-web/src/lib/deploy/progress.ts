/**
 * Rollout progress of one change request (pure: no I/O), for the progress bar on the change-request pages.
 *
 * Stages are derived from what the pipeline already records — no new state:
 *  - Deployment.status (QUEUED → SENDING → SENT → SUCCEEDED / FAILED / TIMED_OUT);
 *  - Deployment.note: the connector pump parks waiting deployments with "waiting for …" notes
 *    (WAITING_NOTE_PREFIX in connector-state.ts: "waiting for Windows update files: …" / "waiting for the site cache");
 *  - the deployment's active connector job (QUEUED / DELIVERED): CACHE_PACKAGE = caching, DEPLOY_* / WU_INSTALL = installing;
 *  - Endpoint.rebootRequired while the install is being confirmed (SENT) = reboot pending.
 */

export const DEPLOY_STAGES = ["queued", "downloading", "caching", "installing", "reboot", "succeeded", "failed"] as const;
export type DeployStage = (typeof DEPLOY_STAGES)[number];

export const STAGE_LABEL: Readonly<Record<DeployStage, string>> = {
  queued: "Queued",
  downloading: "Files downloading / verifying",
  caching: "Caching at site",
  installing: "Installing",
  reboot: "Reboot pending",
  succeeded: "Succeeded",
  failed: "Failed",
};

/** Same text as WAITING_NOTE_PREFIX (connector-state.ts, server-only). */
const WAITING = "waiting for ";
const WAITING_FILES = `${WAITING}windows update files`;
const WAITING_CACHE = `${WAITING}the site cache`;

export interface DeploymentForProgress {
  status: string;
  note?: string | null;
  error?: string | null;
  /** Type of the deployment's QUEUED / DELIVERED connector job, if any */
  activeJobType?: string | null;
  /** The PC reported that it needs a restart to finish installing */
  rebootRequired?: boolean;
}

function waitingStage(note: string | null | undefined): DeployStage | null {
  const n = (note ?? "").toLowerCase();
  if (n.startsWith(WAITING_FILES)) return "downloading";
  if (n.startsWith(WAITING_CACHE)) return "caching";
  return null;
}

/** Current stage of one endpoint's deployment. */
export function deploymentStage(d: DeploymentForProgress): DeployStage {
  switch (d.status) {
    case "SUCCEEDED":
      return "succeeded";
    case "FAILED":
    case "TIMED_OUT":
      return "failed";
    case "SENT":
      return d.rebootRequired ? "reboot" : "installing";
  }
  if (d.activeJobType === "CACHE_PACKAGE") return "caching";
  if (d.activeJobType && (d.activeJobType === "WU_INSTALL" || d.activeJobType.startsWith("DEPLOY_"))) return "installing";
  const waiting = waitingStage(d.note);
  if (waiting) return waiting;
  return d.status === "SENDING" ? "installing" : "queued";
}

/** Why an unfinished deployment waits (the pipeline's note), or null. Finished ones have none. */
export function waitReason(d: DeploymentForProgress): string | null {
  if (d.status === "SUCCEEDED" || d.status === "FAILED" || d.status === "TIMED_OUT") return null;
  const note = d.note?.trim();
  return note ? note : null;
}

export interface RolloutProgress {
  total: number;
  succeeded: number;
  failed: number;
  /** SENDING + SENT (anything started but not finished) */
  inProgress: number;
  queued: number;
  /** succeeded + failed */
  finished: number;
  /** finished / total, 0–100 (whole number; 100 only when everything finished) */
  percent: number;
  stages: Record<DeployStage, number>;
}

/** Counts + per-stage breakdown of a rollout. `total` = the deployments (one per target endpoint). */
export function rolloutProgress(deployments: readonly DeploymentForProgress[]): RolloutProgress {
  const stages = Object.fromEntries(DEPLOY_STAGES.map((s) => [s, 0])) as Record<DeployStage, number>;
  let succeeded = 0;
  let failed = 0;
  let inProgress = 0;
  let queued = 0;
  for (const d of deployments) {
    stages[deploymentStage(d)] += 1;
    if (d.status === "SUCCEEDED") succeeded += 1;
    else if (d.status === "FAILED" || d.status === "TIMED_OUT") failed += 1;
    else if (d.status === "QUEUED") queued += 1;
    else inProgress += 1;
  }
  const total = deployments.length;
  const finished = succeeded + failed;
  return { total, succeeded, failed, inProgress, queued, finished, percent: percentOf(finished, total), stages };
}

/** Progress from status counts only (change-requests list: no per-endpoint detail). */
export function progressFromCounts(counts: Readonly<Record<string, number>>): RolloutProgress {
  const n = (s: string): number => Math.max(0, Math.trunc(counts[s] ?? 0));
  const succeeded = n("SUCCEEDED");
  const failed = n("FAILED") + n("TIMED_OUT");
  const queued = n("QUEUED");
  const inProgress = n("SENDING") + n("SENT");
  const total = succeeded + failed + queued + inProgress;
  const finished = succeeded + failed;
  const stages = { queued, downloading: 0, caching: 0, installing: inProgress, reboot: 0, succeeded, failed };
  return { total, succeeded, failed, inProgress, queued, finished, percent: percentOf(finished, total), stages };
}

export function percentOf(part: number, total: number): number {
  if (total <= 0) return 0;
  const p = Math.floor((part / total) * 100);
  return part >= total ? 100 : Math.min(99, Math.max(0, p));
}
