import { z } from "zod";
import { getCurrentUser, requireSameOrigin, requireWriter } from "@/lib/auth/session";
import { handle, ok } from "@/lib/api/response";
import { PLATFORM_SCOPE, getNotificationSettings, settingsActionSchema, updateNotificationSettings } from "@/lib/notify/settings";

const scopeSchema = z.string().trim().min(1).max(64);

/** GET /api/notifications/settings?scope=platform|<bankId> — bank admins: own bank (default); platform admins: any. */
export async function GET(req: Request): Promise<Response> {
  return handle(async () => {
    const user = await getCurrentUser();
    const raw = new URL(req.url).searchParams.get("scope");
    const scope = scopeSchema.parse(raw ?? user.tenantId ?? PLATFORM_SCOPE);
    const res = ok(await getNotificationSettings(user, scope));
    res.headers.set("Cache-Control", "no-store");
    return res;
  });
}

/** POST { scope, action: "add-webhook" | "remove-webhook" | "set-events", … } — audited. */
export async function POST(req: Request): Promise<Response> {
  return handle(async () => {
    requireSameOrigin(req);
    const user = await getCurrentUser();
    requireWriter(user);
    const body = (await req.json().catch(() => null)) as { scope?: unknown } | null;
    const scope = scopeSchema.parse(body?.scope);
    const action = settingsActionSchema.parse(body);
    const res = ok(await updateNotificationSettings(user, scope, action));
    res.headers.set("Cache-Control", "no-store");
    return res;
  });
}
