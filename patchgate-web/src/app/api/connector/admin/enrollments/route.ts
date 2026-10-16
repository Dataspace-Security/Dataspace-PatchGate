import { getCurrentUser, requireSameOrigin } from "@/lib/auth/session";
import { handle, ok } from "@/lib/api/response";
import { createEnrollmentCode } from "@/lib/connector/admin";

/**
 * Platform admins: create a one-time enrolment code for a bank site. The code is returned ONCE (only its
 * SHA-256 is stored) together with the exact `init` command for the connector host.
 */
export async function POST(req: Request): Promise<Response> {
  return handle(async () => {
    requireSameOrigin(req);
    const user = await getCurrentUser();
    const input: unknown = await req.json().catch(() => null);
    return ok(await createEnrollmentCode(user, input, new URL(req.url).origin), 201);
  });
}
