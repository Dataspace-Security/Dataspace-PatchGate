import { getCurrentUser } from "@/lib/auth/session";
import { handle, ok } from "@/lib/api/response";
import { listOutbox, outboxCounts } from "@/lib/notify/settings";

/** GET /api/notifications/outbox?filter=recent|failed — platform admins only. */
export async function GET(req: Request): Promise<Response> {
  return handle(async () => {
    const user = await getCurrentUser();
    const filter = new URL(req.url).searchParams.get("filter") === "failed" ? "failed" : "recent";
    const res = ok({ counts: await outboxCounts(user), rows: await listOutbox(user, filter) });
    res.headers.set("Cache-Control", "no-store");
    return res;
  });
}
