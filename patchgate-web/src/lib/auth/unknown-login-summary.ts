import "server-only";
import { appendAudit } from "@/lib/audit/service";

/**
 * Failed sign-ins for UNKNOWN user names are not audited one by one: the name is attacker-supplied, the
 * platform chain is serialised by an advisory lock, and spraying random names would otherwise turn the audit
 * log into an unbounded, lock-contended write amplifier. Instead they are counted (per client IP, bounded
 * memory) and written as ONE summary event ("auth.failed_unknown_summary", platform chain) at most once per
 * window — flushed by the next failure after the window or by the worker tick. The names themselves are
 * never stored. Failures for KNOWN users and lockouts are still audited individually on the user's chain.
 */

export const SUMMARY_WINDOW_MS = 60_000;
const MAX_TRACKED_IPS = 1000;
const TOP_IPS = 10;

interface Window {
  startedAt: number;
  failures: number;
  byIp: Map<string, number>;
  untrackedIpFailures: number;
}

let current: Window | null = null;

const fresh = (now: number): Window => ({ startedAt: now, failures: 0, byIp: new Map(), untrackedIpFailures: 0 });

/** Count one failed sign-in for an unknown user name. Flushes the previous window when it has elapsed. */
export async function recordUnknownUserFailure(ip: string | null, now = Date.now()): Promise<void> {
  if (current && now - current.startedAt >= SUMMARY_WINDOW_MS) await flushUnknownLoginSummary(now);
  current ??= fresh(now);
  current.failures++;
  const key = ip ?? "unknown";
  if (current.byIp.has(key) || current.byIp.size < MAX_TRACKED_IPS) current.byIp.set(key, (current.byIp.get(key) ?? 0) + 1);
  else current.untrackedIpFailures++;
}

/** Write the summary of the elapsed window (no-op when nothing was counted or the window is still open). */
export async function flushUnknownLoginSummary(now = Date.now(), force = false): Promise<number> {
  const w = current;
  if (!w || w.failures === 0) return 0;
  if (!force && now - w.startedAt < SUMMARY_WINDOW_MS) return 0;
  current = null;
  const topIps = [...w.byIp.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, TOP_IPS)
    .map(([ip, count]) => ({ ip, count }));
  await appendAudit({
    actor: "system:auth",
    action: "auth.failed_unknown_summary",
    entity: "User",
    entityId: "-",
    payload: {
      reason: "unknown user",
      failures: w.failures,
      distinctIps: w.byIp.size + (w.untrackedIpFailures > 0 ? 1 : 0),
      untrackedIpFailures: w.untrackedIpFailures,
      topIps,
      windowStart: new Date(w.startedAt).toISOString(),
      windowEnd: new Date(now).toISOString(),
    },
    tenantId: null,
  });
  return w.failures;
}

/** Test hook: drop the in-memory window. */
export function resetUnknownLoginSummary(): void {
  current = null;
}
