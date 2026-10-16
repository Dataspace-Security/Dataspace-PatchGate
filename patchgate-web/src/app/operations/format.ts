import type { Tone } from "@/components/ui";
import type { Rag } from "@/lib/metrics/thresholds";

export const RAG_TONE: Record<Rag, Tone> = { green: "good", amber: "warn", red: "bad", none: "neutral" };
export const RAG_LABEL: Record<Rag, string> = { green: "OK", amber: "Warning", red: "Action needed", none: "No data" };
export const STAT_TONE: Record<Rag, "neutral" | "good" | "warn" | "bad"> = { green: "good", amber: "warn", red: "bad", none: "neutral" };

/** 42 s · 7 min · 3 h 10 min · 2 d 4 h · never */
export function fmtAge(sec: number | null | undefined): string {
  if (sec === null || sec === undefined) return "—";
  if (!Number.isFinite(sec)) return "never";
  if (sec < 60) return `${Math.round(sec)} s`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min} min`;
  const h = Math.floor(min / 60);
  if (h < 48) return min % 60 ? `${h} h ${min % 60} min` : `${h} h`;
  const d = Math.floor(h / 24);
  return h % 24 ? `${d} d ${h % 24} h` : `${d} d`;
}

export function fmtBytes(n: number | null | undefined): string {
  if (n === null || n === undefined) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v >= 10 || i === 0 ? Math.round(v) : v.toFixed(1)} ${units[i]}`;
}

export function fmtMs(ms: number): string {
  return ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(ms < 10_000 ? 1 : 0)} s`;
}

export function fmtPct(v: number | null): string {
  return v === null ? "—" : `${v.toFixed(v >= 99.95 || v === 0 ? 0 : 1)} %`;
}

export function secondsSince(d: Date | null | undefined, now: Date): number | null {
  return d ? Math.max(0, (now.getTime() - d.getTime()) / 1000) : null;
}
