/**
 * Live refresh of open pages (pure, shared by the client indicator and the pages).
 *
 * Pages re-render on the server (router.refresh) every LIVE_ACTIVE_MS while there is active work
 * (deployment running, connector jobs queued / delivered) and every LIVE_IDLE_MS otherwise; never while
 * the browser tab is hidden. This only adds load on the PatchGate web server — the bank LAN is untouched
 * (site connectors keep polling on their own schedule).
 */

export const LIVE_ACTIVE_MS = 5_000;
export const LIVE_IDLE_MS = 30_000;

export function liveIntervalMs(active: boolean): number {
  return active ? LIVE_ACTIVE_MS : LIVE_IDLE_MS;
}

/** Should a refresh run now? (`lastMs` = when the page was last refreshed) */
export function refreshDue(nowMs: number, lastMs: number, active: boolean, hidden: boolean): boolean {
  if (hidden) return false;
  return nowMs - lastMs >= liveIntervalMs(active);
}

/** "updated just now" / "updated 12s ago" / "updated 3 min ago" — never negative (clock jumps). */
export function updatedAgoText(nowMs: number, lastMs: number): string {
  const s = Math.floor((nowMs - lastMs) / 1000);
  if (!Number.isFinite(s) || s < 2) return "updated just now";
  if (s < 120) return `updated ${s}s ago`;
  return `updated ${Math.floor(s / 60)} min ago`;
}
