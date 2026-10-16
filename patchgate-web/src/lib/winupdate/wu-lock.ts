/**
 * Windows Update lock (pure: no I/O). The PC-side scan script reports whether the Windows Update policies
 * that stop the PC from taking updates from Microsoft by itself are in place (RUNBOOK "PatchGate locks
 * Windows Update"). PatchGate stores the state per endpoint and alerts when a PC is NOT locked.
 */

export interface WuLockReport {
  locked: boolean;
  issues: string[];
  lastOutsideInstall?: { at: string; title: string } | null;
}

export interface WuLockDetail {
  issues: string[];
  lastOutsideInstall: { at: string; title: string } | null;
}

/**
 * broken   = now NOT locked and before locked or never reported (first report of an unlocked PC alerts too);
 * restored = locked again after having been NOT locked;
 * none     = no change (an unlocked PC that stays unlocked does not alert again on every scan).
 */
export type WuLockTransition = "broken" | "restored" | "none";

export function wuLockTransition(previous: boolean | null, next: boolean): WuLockTransition {
  if (!next && previous !== false) return "broken";
  if (next && previous === false) return "restored";
  return "none";
}

export function wuLockDetail(r: WuLockReport): WuLockDetail {
  return { issues: r.issues.slice(0, 20), lastOutsideInstall: r.lastOutsideInstall ?? null };
}

/** Read a stored detail defensively (JSON column). */
export function readWuLockDetail(v: unknown): WuLockDetail {
  const o = (typeof v === "object" && v !== null ? v : {}) as Record<string, unknown>;
  const issues = Array.isArray(o.issues) ? o.issues.filter((i): i is string => typeof i === "string") : [];
  const l = o.lastOutsideInstall as Record<string, unknown> | null | undefined;
  const lastOutsideInstall = l && typeof l.at === "string" && typeof l.title === "string" ? { at: l.at, title: l.title } : null;
  return { issues, lastOutsideInstall };
}
