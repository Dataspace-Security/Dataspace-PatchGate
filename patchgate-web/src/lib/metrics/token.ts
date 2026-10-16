import { tokenMatches } from "@/lib/api/token";

/** Minimum length of METRICS_TOKEN (also enforced by src/lib/env.ts). */
export const METRICS_TOKEN_MIN = 32;

/** "Bearer <token>" → token; anything else → null. Scheme is case-insensitive (RFC 7235). */
export function bearerToken(header: string | null | undefined): string | null {
  if (!header) return null;
  const m = /^Bearer[ \t]+([^\s]+)[ \t]*$/i.exec(header);
  return m ? m[1] : null;
}

export type MetricsAuth = "ok" | "disabled" | "unauthorized";

/**
 * /api/metrics access: disabled (404) when METRICS_TOKEN is not configured; otherwise the bearer token must
 * match in constant time. Never says which part was wrong.
 */
export function checkMetricsAuth(authorization: string | null | undefined, expected: string | undefined): MetricsAuth {
  if (!expected || expected.length < METRICS_TOKEN_MIN) return "disabled";
  return tokenMatches(bearerToken(authorization), expected) ? "ok" : "unauthorized";
}
