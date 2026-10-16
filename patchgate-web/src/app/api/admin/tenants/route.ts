import { getCurrentUser, requireSameOrigin, requireWriter } from "@/lib/auth/session";
import { handle, ok } from "@/lib/api/response";
import { createTenant, createTenantSchema, listTenants } from "@/lib/auth/admin-service";

/** Banks: platform admins see all, bank admins only their own. */
export async function GET(): Promise<Response> {
  return handle(async () => ok(await listTenants(await getCurrentUser())));
}

/** Onboard a bank (platform admins only). */
export async function POST(req: Request): Promise<Response> {
  return handle(async () => {
    requireSameOrigin(req);
    const actor = await getCurrentUser();
    requireWriter(actor);
    const input = createTenantSchema.parse(await req.json().catch(() => null));
    return ok(await createTenant(actor, input), 201);
  });
}
