import { connection } from "next/server";
import { recordHeartbeat } from "@/lib/connector/heartbeat";
import { json, parseJsonBody, withConnector } from "@/lib/connector/http";
import { BODY_LIMITS } from "@/lib/connector/policy";

/** Heartbeat: store health, answer with the bank's LAN limits (they can only lower the connector's own). */
export async function POST(req: Request): Promise<Response> {
  await connection();
  return withConnector(req, "heartbeat", BODY_LIMITS.heartbeat, async ({ connector, body }) =>
    json(await recordHeartbeat(connector, parseJsonBody(body))),
  );
}
