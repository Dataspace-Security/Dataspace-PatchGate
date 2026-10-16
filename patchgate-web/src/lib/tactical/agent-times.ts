/**
 * Agent times from Tactical RMM (pure). Tactical's agent list (GET /agents/) carries
 *  - `last_seen`: when the Tactical server last heard from the agent — an ISO 8601 DateTime from the
 *    Tactical server's clock (DRF renders it with an offset / "Z"; a value without one is treated as UTC);
 *  - `boot_time`: when the PC booted — Unix epoch SECONDS (float) from the PC's OWN clock.
 *
 * Both can be wrong: a PC whose clock runs ahead reports a boot time in the future (Tactical then shows
 * "Boot Time: -14543 seconds ago"), and the Tactical server clock may differ from ours. Rules:
 *  - everything is stored as a UTC instant (Date);
 *  - a time slightly in the future (≤ the tolerance) is clamped to "now"; further in the future, before
 *    2000-01-01 or unparsable → null ("unknown"), never a negative duration.
 */

const MIN_PLAUSIBLE_MS = Date.UTC(2000, 0, 1);
/** Tactical server vs PatchGate clock: tolerate up to a day ahead (then clamp to now). */
export const LAST_SEEN_FUTURE_TOLERANCE_MS = 24 * 60 * 60_000;
/** The PC's clock (boot_time): tolerate 10 minutes ahead; beyond that the value is unknown. */
export const BOOT_FUTURE_TOLERANCE_MS = 10 * 60_000;
/** Epoch values above this are milliseconds, not seconds (year 33658 in seconds). */
const EPOCH_MS_THRESHOLD = 1e12;

const HAS_ZONE = /(?:[zZ]|[+-]\d{2}(?::?\d{2})?)$/;
const ISO_LIKE = /^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?)?/;
const NUMERIC = /^-?\d+(?:\.\d+)?$/;

function fromEpoch(n: number): Date | null {
  if (!Number.isFinite(n) || n <= 0) return null;
  const d = new Date(n >= EPOCH_MS_THRESHOLD ? n : n * 1000);
  return Number.isNaN(d.getTime()) ? null : d;
}

/** Parse a Tactical time value (ISO string, epoch seconds / ms as number or numeric string) to a UTC Date. */
export function parseTacticalTime(v: unknown): Date | null {
  if (v instanceof Date) return Number.isNaN(v.getTime()) ? null : v;
  if (typeof v === "number") return fromEpoch(v);
  if (typeof v !== "string") return null;
  const s = v.trim();
  if (s === "") return null;
  if (NUMERIC.test(s)) return fromEpoch(Number(s));
  if (!ISO_LIKE.test(s)) return null;
  // No offset → UTC (never the server's local timezone).
  const iso = HAS_ZONE.test(s) ? s.replace(" ", "T") : `${s.replace(" ", "T")}${s.length <= 10 ? "T00:00:00" : ""}Z`;
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? null : d;
}

/** Plausible UTC instant ≤ now, or null (see the rules above). */
export function normaliseAgentTime(v: unknown, now: Date, futureToleranceMs: number): Date | null {
  const d = parseTacticalTime(v);
  if (!d) return null;
  const t = d.getTime();
  if (t < MIN_PLAUSIBLE_MS) return null;
  if (t > now.getTime() + futureToleranceMs) return null;
  return t > now.getTime() ? new Date(now.getTime()) : d;
}

export interface AgentTimeInput {
  /** Tactical last_seen */
  lastSeen?: unknown;
  /** Tactical boot_time */
  bootTime?: unknown;
  /** Tactical status === "online" (null = not reported) */
  online?: boolean | null;
}

export interface AgentTimes {
  /** null = keep what PatchGate knew (agent offline and no usable last_seen) */
  lastSeenAt: Date | null;
  bootedAt: Date | null;
}

/**
 * Endpoint times for one agent of a sync at `now`. Without a usable Tactical last_seen, an agent the
 * connector reports as online (or whose status is unknown — older connectors) was seen at sync time; an
 * agent reported OFFLINE keeps its previous value (null here) instead of looking freshly seen.
 */
export function agentTimes(a: AgentTimeInput, now: Date): AgentTimes {
  const seen = normaliseAgentTime(a.lastSeen, now, LAST_SEEN_FUTURE_TOLERANCE_MS);
  return {
    lastSeenAt: seen ?? (a.online === false ? null : new Date(now.getTime())),
    bootedAt: normaliseAgentTime(a.bootTime, now, BOOT_FUTURE_TOLERANCE_MS),
  };
}

/** "just now" / "5 min ago" / "3 h ago" / "12 days ago" / "unknown" — never a negative duration. */
export function formatAgo(d: Date | null | undefined, now: Date): string {
  if (!d || Number.isNaN(d.getTime())) return "unknown";
  const s = Math.floor((now.getTime() - d.getTime()) / 1000);
  if (s < 60) return "just now"; // includes small clock skew (negative)
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} min ago`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h} h ago`;
  return `${Math.floor(h / 24)} days ago`;
}
