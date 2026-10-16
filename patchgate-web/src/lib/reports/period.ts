/**
 * Report periods (pure). All periods are half-open UTC ranges [from, to):
 *  - month   "YYYY-MM"            (default: current month)
 *  - quarter "YYYY-Qn"            (default: current quarter)
 *  - custom  from/to "YYYY-MM-DD" (to inclusive; at most 400 days)
 */

export type PeriodKind = "month" | "quarter" | "custom";

export interface Period {
  kind: PeriodKind;
  from: Date;
  to: Date;
  label: string;
  /** Canonical query string for links / exports */
  query: string;
}

export interface PeriodParams {
  period?: string | null;
  month?: string | null;
  quarter?: string | null;
  from?: string | null;
  to?: string | null;
}

export class PeriodError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PeriodError";
  }
}

const MAX_CUSTOM_DAYS = 400;
const DAY_MS = 86_400_000;
const MONTH_RE = /^(\d{4})-(0[1-9]|1[0-2])$/;
const QUARTER_RE = /^(\d{4})-Q([1-4])$/i;
const DATE_RE = /^(\d{4})-(\d{2})-(\d{2})$/;

function utc(y: number, m0: number, d = 1): Date {
  return new Date(Date.UTC(y, m0, d));
}

function ymd(d: Date): string {
  return d.toISOString().slice(0, 10);
}

function parseDate(raw: string, what: string): Date {
  const m = DATE_RE.exec(raw);
  if (!m) throw new PeriodError(`${what}: expected YYYY-MM-DD`);
  const d = utc(Number(m[1]), Number(m[2]) - 1, Number(m[3]));
  if (ymd(d) !== raw) throw new PeriodError(`${what}: not a calendar date`);
  return d;
}

export function monthPeriod(y: number, m0: number): Period {
  const from = utc(y, m0);
  const key = `${y}-${String(m0 + 1).padStart(2, "0")}`;
  return { kind: "month", from, to: utc(y, m0 + 1), label: from.toLocaleString("en-GB", { month: "long", year: "numeric", timeZone: "UTC" }), query: `period=month&month=${key}` };
}

export function quarterPeriod(y: number, q: number): Period {
  return { kind: "quarter", from: utc(y, (q - 1) * 3), to: utc(y, q * 3), label: `Q${q} ${y}`, query: `period=quarter&quarter=${y}-Q${q}` };
}

export function parsePeriod(p: PeriodParams, now = new Date()): Period {
  const kind = (p.period ?? "month").toLowerCase();
  if (kind === "month") {
    if (!p.month) return monthPeriod(now.getUTCFullYear(), now.getUTCMonth());
    const m = MONTH_RE.exec(p.month);
    if (!m) throw new PeriodError("month: expected YYYY-MM");
    return monthPeriod(Number(m[1]), Number(m[2]) - 1);
  }
  if (kind === "quarter") {
    if (!p.quarter) return quarterPeriod(now.getUTCFullYear(), Math.floor(now.getUTCMonth() / 3) + 1);
    const m = QUARTER_RE.exec(p.quarter);
    if (!m) throw new PeriodError("quarter: expected YYYY-Qn");
    return quarterPeriod(Number(m[1]), Number(m[2]));
  }
  if (kind === "custom") {
    if (!p.from || !p.to) throw new PeriodError("custom period: from and to are required");
    const from = parseDate(p.from, "from");
    const last = parseDate(p.to, "to");
    if (last < from) throw new PeriodError("custom period: to is before from");
    const to = new Date(last.getTime() + DAY_MS);
    if ((to.getTime() - from.getTime()) / DAY_MS > MAX_CUSTOM_DAYS) throw new PeriodError(`custom period: at most ${MAX_CUSTOM_DAYS} days`);
    return { kind: "custom", from, to, label: `${p.from} – ${p.to}`, query: `period=custom&from=${p.from}&to=${p.to}` };
  }
  throw new PeriodError("period: month, quarter or custom");
}

/** Overlap in ms of [a0, a1) and [b0, b1). */
export function overlapMs(a0: Date, a1: Date, b0: Date, b1: Date): number {
  return Math.max(0, Math.min(a1.getTime(), b1.getTime()) - Math.max(a0.getTime(), b0.getTime()));
}

/** Days between a release date and `asOf` → report age bucket. */
export type AgeBucket = "0-7" | "8-30" | "31-90" | ">90" | "unknown";
export const AGE_BUCKETS: readonly AgeBucket[] = ["0-7", "8-30", "31-90", ">90", "unknown"];

export function ageBucket(releasedAt: Date | null, asOf: Date): AgeBucket {
  if (!releasedAt) return "unknown";
  const days = Math.floor((asOf.getTime() - releasedAt.getTime()) / DAY_MS);
  if (days <= 7) return "0-7";
  if (days <= 30) return "8-30";
  if (days <= 90) return "31-90";
  return ">90";
}
