import { connection } from "next/server";
import { json, parseJsonBody, withConnector } from "@/lib/connector/http";
import { BODY_LIMITS } from "@/lib/connector/policy";
import { ingestTacticalPush } from "@/lib/connector/tactical-push";

/** Real-time Tactical guard (protocol §8): out-of-band audit entries + approvals the connector reset. */
export async function POST(req: Request): Promise<Response> {
  await connection();
  return withConnector(req, "tactical-events", BODY_LIMITS.tacticalEvents, async ({ connector, body }) =>
    json(await ingestTacticalPush(connector, parseJsonBody(body))),
  );
}
