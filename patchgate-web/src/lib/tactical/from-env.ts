import "server-only";
import { env } from "@/lib/env";
import { DomainError } from "@/lib/errors";
import { createTacticalClient, type TacticalClient } from "./client";

/**
 * The direct (env-configured) Tactical link serves ONE legacy bank. Hosted deployments where every bank
 * has a site connector do not configure it: TACTICAL_API_URL / TACTICAL_API_KEY / PATCH_REPO_URL may be
 * absent, and the legacy steps are skipped with a clear status instead of failing.
 */

interface DirectTacticalConfig {
  baseUrl: string;
  apiKey: string;
  repoUrl: string;
  timeoutMs: number;
}

/** The direct link's settings, or null when it is not configured (hosted mode). */
export function directTacticalConfig(): DirectTacticalConfig | null {
  const e = env();
  // Read as optional: env.ts makes these optional for hosted mode.
  const baseUrl: string | undefined = e.TACTICAL_API_URL || undefined;
  const apiKey: string | undefined = e.TACTICAL_API_KEY || undefined;
  const repoUrl: string | undefined = e.PATCH_REPO_URL || undefined;
  if (!baseUrl || !apiKey || !repoUrl) return null;
  return { baseUrl, apiKey, repoUrl, timeoutMs: e.TACTICAL_TIMEOUT_MS };
}

export const DIRECT_TACTICAL_NOT_CONFIGURED = "skipped: direct Tactical link not configured (hosted mode)";

/** Direct Tactical client, or null when the direct link is not configured. */
export function tacticalFromEnvOrNull(): TacticalClient | null {
  const c = directTacticalConfig();
  return c ? createTacticalClient({ baseUrl: c.baseUrl, apiKey: c.apiKey, timeoutMs: c.timeoutMs }) : null;
}

/** Direct Tactical client; throws a clear error when the direct link is not configured. */
export function tacticalFromEnv(): TacticalClient {
  const t = tacticalFromEnvOrNull();
  if (!t) throw new DomainError("The direct Tactical link is not configured (TACTICAL_API_URL / TACTICAL_API_KEY / PATCH_REPO_URL)", 409);
  return t;
}

/** The single bank served by the direct (env-configured) Tactical connection. */
export function legacyTacticalTenantId(): string {
  return env().LEGACY_TACTICAL_TENANT_ID;
}

/**
 * Direct Tactical client for a bank — only the legacy bank has one. Every other bank's PCs are reached
 * through its own site connector, never through our env-configured Tactical server.
 */
export function tacticalForTenant(tenantId: string): TacticalClient {
  if (tenantId !== legacyTacticalTenantId()) {
    throw new DomainError("This bank's PCs are managed through its site connector, not the direct Tactical link", 409);
  }
  return tacticalFromEnv();
}
