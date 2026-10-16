import "server-only";
import { appendAudit } from "@/lib/audit/service";
import { mfaDisabled } from "@/lib/env";
import { log } from "@/lib/log";

/** Audit action written (platform chain) once per process start while local sign-in runs without TOTP. */
export const MFA_DISABLED_ACTION = "auth.mfa_disabled";

/** User-facing warning (banner for admins, /operations). */
export const MFA_OFF_WARNING = "Two-factor sign-in is OFF — turn AUTH_MFA=required on before go-live.";

// Process-wide (survives module re-instantiation between the instrumentation and route bundles).
const STATE = Symbol.for("patchgate.mfaDisabledAnnounced");
type Holder = { [STATE]?: Promise<boolean> };

async function writeEvent(): Promise<boolean> {
  try {
    await appendAudit({
      actor: "system:config",
      action: MFA_DISABLED_ACTION,
      entity: "Config",
      entityId: "AUTH_MFA",
      payload: { AUTH_MFA: "off", authMode: "local", pid: process.pid, warning: MFA_OFF_WARNING },
      tenantId: null,
    });
    log.warn("auth.mfa_disabled", { authMfa: "off" });
    return true;
  } catch (err: unknown) {
    log.error("auth.mfa_disabled.audit_failed", { err });
    delete (globalThis as Holder)[STATE]; // try again on the next call
    return false;
  }
}

/**
 * When AUTH_MFA=off (local sign-in): append `auth.mfa_disabled` to the platform audit chain — once per
 * process. Returns whether an event was written by THIS call. Never throws (start-up must not fail on it).
 */
export async function announceMfaDisabledOnce(): Promise<boolean> {
  let off: boolean;
  try {
    off = mfaDisabled();
  } catch {
    return false; // invalid configuration is reported by env() on the first real request
  }
  if (!off) return false;
  const holder = globalThis as Holder;
  if (holder[STATE]) {
    await holder[STATE];
    return false;
  }
  const p = writeEvent();
  holder[STATE] = p;
  return p;
}
