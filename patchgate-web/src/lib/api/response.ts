import "server-only";
import { unstable_rethrow } from "next/navigation";
import { ZodError } from "zod";
import { AuthError } from "@/lib/auth/session";
import { DomainError } from "@/lib/errors";
import { TacticalError } from "@/lib/tactical/client";

export interface ApiResponse<T> {
  success: boolean;
  data: T | null;
  error: string | null;
}

export function ok<T>(data: T, status = 200): Response {
  return Response.json({ success: true, data, error: null } satisfies ApiResponse<T>, { status });
}

export function fail(error: string, status: number): Response {
  return Response.json({ success: false, data: null, error } satisfies ApiResponse<null>, {
    status,
  });
}

/** Map known errors to safe responses; never leak internals. */
export async function handle(fn: () => Promise<Response>): Promise<Response> {
  try {
    return await fn();
  } catch (err: unknown) {
    unstable_rethrow(err); // let Next.js internal control-flow errors through
    if (err instanceof AuthError) return fail(err.message, err.status);
    if (err instanceof ZodError) {
      // Field + schema message only (e.g. "allowedDomains.0: internal hostnames are not allowed").
      const first = err.issues[0];
      const where = first?.path.length ? `${first.path.join(".")}: ` : "";
      return fail(`Invalid request — ${where}${first?.message ?? "malformed body"}`, 400);
    }
    if (err instanceof DomainError) return fail(err.message, err.status);
    if (err instanceof TacticalError) {
      // Operators need to know it is Tactical, not PatchGate, that failed — without leaking internals.
      console.error("[patchgate] Tactical RMM call failed", err.message);
      return err.status === undefined
        ? fail("Tactical RMM is unreachable — check the Tactical server and network, then retry.", 502)
        : fail(`Tactical RMM rejected the request (HTTP ${err.status}). Check the PatchGate API key permissions.`, 502);
    }
    console.error("[patchgate] unhandled API error", err);
    return fail("Internal error", 500);
  }
}
