import { connection } from "next/server";
import { authMode, env, mfaRequired } from "@/lib/env";

/** "required" | "off" for local sign-in (AUTH_MFA); "n/a" for SSO / dev or when the configuration is invalid. */
function mfaStatus(): "required" | "off" | "n/a" {
  try {
    const e = env();
    if (authMode(e) !== "local") return "n/a";
    return mfaRequired(e) ? "required" : "off";
  } catch {
    return "n/a"; // liveness never depends on configuration
  }
}

/**
 * Liveness: the process is up and serving (no dependencies). For the load balancer / orchestrator.
 * `mfa` flags local sign-in without the second factor (AUTH_MFA=off) so monitoring can alert on it.
 */
export async function GET(): Promise<Response> {
  await connection();
  return Response.json({ status: "ok", mfa: mfaStatus() }, { headers: { "Cache-Control": "no-store" } });
}
