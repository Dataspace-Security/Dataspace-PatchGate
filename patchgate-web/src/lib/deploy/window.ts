import { CronExpressionParser } from "cron-parser";

/** Maintenance window = cron start time (in the ring's timezone) + duration. */
export interface WindowSpec {
  cron: string;
  durationMin: number;
  timezone: string;
}

/** True if `now` falls in [lastStart, lastStart + duration). Invalid specs fail closed. */
export function isWithinWindow(w: WindowSpec, now: Date): boolean {
  try {
    // prev() is strictly before currentDate, so step 1s ahead to include the exact start.
    const interval = CronExpressionParser.parse(w.cron, {
      currentDate: new Date(now.getTime() + 1000),
      tz: w.timezone,
    });
    const lastStart = interval.prev().toDate().getTime();
    return now.getTime() >= lastStart && now.getTime() < lastStart + w.durationMin * 60_000;
  } catch {
    return false;
  }
}

/** The window occurrence `now` falls in ({ start, end }), or null outside any window (invalid specs fail closed). */
export function currentWindow(w: WindowSpec, now: Date): { start: Date; end: Date } | null {
  try {
    const interval = CronExpressionParser.parse(w.cron, {
      currentDate: new Date(now.getTime() + 1000),
      tz: w.timezone,
    });
    const start = interval.prev().toDate().getTime();
    const end = start + w.durationMin * 60_000;
    return now.getTime() >= start && now.getTime() < end ? { start: new Date(start), end: new Date(end) } : null;
  } catch {
    return null;
  }
}
