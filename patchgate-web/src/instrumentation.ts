/**
 * Runs once when a PatchGate server process starts (Next.js instrumentation `register`).
 * Node.js runtime only; skipped while `next build` prerenders. Start-up never waits on or fails because of it.
 */
export async function register(): Promise<void> {
  if (process.env.NEXT_RUNTIME !== "nodejs") return;
  if (process.env.NEXT_PHASE === "phase-production-build") return;
  const { announceMfaDisabledOnce } = await import("@/lib/auth/mfa-status");
  void announceMfaDisabledOnce();
}
