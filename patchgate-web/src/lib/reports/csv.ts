import { createHash } from "node:crypto";

/** CSV + canonical-content helpers (pure). */

export type Cell = string | number | boolean | Date | null | undefined | readonly string[];

/**
 * One RFC 4180 cell. Values starting with = + - @ (or tab / CR) are prefixed with an apostrophe so a
 * spreadsheet never evaluates them as formulas (CSV injection) — hostnames / titles come from endpoints.
 */
export function csvCell(v: Cell): string {
  if (v === null || v === undefined) return "";
  let s: string;
  if (v instanceof Date) s = v.toISOString();
  else if (Array.isArray(v)) s = v.join("; ");
  else s = String(v);
  if (typeof v === "string" || Array.isArray(v)) {
    if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  }
  return /[",\r\n;]/.test(s) || s !== s.trim() ? `"${s.replace(/"/g, '""')}"` : s;
}

export function csvLine(cells: readonly Cell[]): string {
  return `${cells.map(csvCell).join(",")}\r\n`;
}

/** Deterministic JSON: sorted keys, Dates as ISO strings, BigInt as strings. */
export function canonicalJson(value: unknown): string {
  const norm = (v: unknown): unknown => {
    if (v === null || v === undefined) return null;
    if (v instanceof Date) return v.toISOString();
    if (typeof v === "bigint") return v.toString();
    if (Array.isArray(v)) return v.map(norm);
    if (typeof v === "object") {
      const o = v as Record<string, unknown>;
      return Object.fromEntries(
        Object.keys(o)
          .sort()
          .filter((k) => o[k] !== undefined)
          .map((k) => [k, norm(o[k])]),
      );
    }
    return v;
  };
  return JSON.stringify(norm(value));
}

/** SHA-256 (hex) of the canonical report content — printed on the report and recorded in the audit event. */
export function contentHash(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value)).digest("hex");
}
