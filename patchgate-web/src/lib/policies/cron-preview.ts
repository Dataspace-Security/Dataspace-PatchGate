import { CronExpressionParser } from "cron-parser";
import { z } from "zod";

/**
 * Maintenance-window validation + preview (pure). A window = 5-field cron start (in the window's timezone)
 * + duration. The preview lists the next occurrences formatted in the BANK's timezone, so bank admins see
 * their local wall-clock time even when a window is defined in another zone.
 */

export const MIN_WINDOW_MIN = 15;
export const MAX_WINDOW_MIN = 24 * 60;
export const PREVIEW_COUNT = 5;

export function isValidTimezone(tz: string): boolean {
  if (!tz || tz.length > 64) return false;
  try {
    new Intl.DateTimeFormat("en-GB", { timeZone: tz });
    return true;
  } catch {
    return false;
  }
}

/** Only classic 5-field cron (minute hour day-of-month month day-of-week); no seconds, no macros. */
const CRON_RE = /^\s*\S+\s+\S+\s+\S+\s+\S+\s+\S+\s*$/;

export type CronCheck = { ok: true } | { ok: false; error: string };

export function checkCron(cron: string, timezone: string): CronCheck {
  if (cron.length > 100 || !CRON_RE.test(cron)) return { ok: false, error: "Use a 5-field cron expression (minute hour day month weekday)" };
  if (!isValidTimezone(timezone)) return { ok: false, error: `Unknown timezone "${timezone.slice(0, 64)}"` };
  try {
    CronExpressionParser.parse(cron.trim(), { tz: timezone });
    return { ok: true };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : "invalid expression";
    return { ok: false, error: `Invalid cron expression: ${msg.slice(0, 120)}` };
  }
}

export interface WindowOccurrence {
  start: Date;
  end: Date;
}

/** Next `count` window occurrences after `from` (empty for an invalid spec). */
export function nextOccurrences(spec: { cron: string; durationMin: number; timezone: string }, from: Date, count = PREVIEW_COUNT): WindowOccurrence[] {
  if (!checkCron(spec.cron, spec.timezone).ok) return [];
  const it = CronExpressionParser.parse(spec.cron.trim(), { currentDate: from, tz: spec.timezone });
  const out: WindowOccurrence[] = [];
  for (let i = 0; i < count; i++) {
    const start = it.next().toDate();
    out.push({ start, end: new Date(start.getTime() + spec.durationMin * 60_000) });
  }
  return out;
}

/** Wall-clock time in a timezone, e.g. "Sun 18 Oct 2026, 02:00 IST". */
export function formatInTimezone(d: Date, timezone: string): string {
  const tz = isValidTimezone(timezone) ? timezone : "UTC";
  return new Intl.DateTimeFormat("en-GB", {
    timeZone: tz,
    weekday: "short",
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
    timeZoneName: "short",
  }).format(d);
}

export const windowInputSchema = z
  .object({
    name: z.string().trim().min(2).max(120),
    ringId: z.string().min(1).max(64),
    cron: z.string().trim().min(9).max(100),
    durationMin: z.coerce.number().int().min(MIN_WINDOW_MIN).max(MAX_WINDOW_MIN),
    timezone: z.string().trim().min(1).max(64),
    rebootPolicy: z.enum(["NEVER", "REQUIRED", "ALWAYS"]).default("REQUIRED"),
  })
  .superRefine((w, ctx) => {
    const c = checkCron(w.cron, w.timezone);
    if (!c.ok) {
      ctx.addIssue({ code: "custom", path: [w.timezone && !isValidTimezone(w.timezone) ? "timezone" : "cron"], message: c.error });
      return;
    }
    // Overlapping occurrences (e.g. hourly start + 2 h duration) make "inside the window" ambiguous.
    const occ = nextOccurrences(w, new Date(), 8);
    for (let i = 1; i < occ.length; i++) {
      if (occ[i]!.start.getTime() < occ[i - 1]!.end.getTime()) {
        ctx.addIssue({ code: "custom", path: ["durationMin"], message: "The window is longer than the gap between two starts (occurrences overlap)" });
        return;
      }
    }
  });
export type WindowInput = z.infer<typeof windowInputSchema>;
