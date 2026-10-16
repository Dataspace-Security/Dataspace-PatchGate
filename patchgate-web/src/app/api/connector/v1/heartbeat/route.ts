import { connection } from "next/server";
import { requestGuardSyncIfNeeded } from "@/lib/connector/guard-sync";
import { recordHeartbeat } from "@/lib/connector/heartbeat";
import { json, parseJsonBody, withConnector } from "@/lib/connector/http";
import { BODY_LIMITS } from "@/lib/connector/policy";

/** Heartbeat: store health, answer with the bank's LAN limits (they can only lower the connector's own). */
export async function POST(req: Request): Promise<Response> {
  await connection();
  return withConnector(req, "heartbeat", BODY_LIMITS.heartbeat, async ({ connector, body }) => {
    const hb = parseJsonBody(body);
    const reply = await recordHeartbeat(connector, hb);
    // Real-time guard (re)started without an allow-set: sign PatchGate's baseline (TACTICAL_GUARD_SYNC).
    await requestGuardSyncIfNeeded(connector, (hb as { guard?: { enabled: boolean; allowSetKnown: boolean } }).guard);
    return json(reply);
  });
}
