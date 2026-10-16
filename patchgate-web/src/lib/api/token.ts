import { timingSafeEqual } from "node:crypto";

/** Constant-time comparison for machine-to-machine shared tokens. */
export function tokenMatches(given: string | null, expected: string | undefined): boolean {
  if (!given || !expected) return false;
  const a = Buffer.from(given);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}
