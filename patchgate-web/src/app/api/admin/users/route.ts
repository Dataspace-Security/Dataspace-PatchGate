import { getCurrentUser, requireSameOrigin, requireWriter } from "@/lib/auth/session";
import { handle, ok } from "@/lib/api/response";
import { createUser, createUserSchema, listUsers } from "@/lib/auth/admin-service";

/** Users the caller administers (platform admin: everyone; bank admin: own bank). */
export async function GET(): Promise<Response> {
  return handle(async () => ok(await listUsers(await getCurrentUser())));
}

/** Create a user with a one-time temporary password (returned once, never stored in clear). */
export async function POST(req: Request): Promise<Response> {
  return handle(async () => {
    requireSameOrigin(req);
    const actor = await getCurrentUser();
    requireWriter(actor);
    const input = createUserSchema.parse(await req.json().catch(() => null));
    const res = ok(await createUser(actor, input), 201);
    res.headers.set("Cache-Control", "no-store");
    return res;
  });
}
