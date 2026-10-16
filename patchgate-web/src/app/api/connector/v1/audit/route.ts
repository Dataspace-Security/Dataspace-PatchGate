import { connection } from "next/server";
import { auditPage, parseAuditQuery } from "@/lib/connector/audit-relay";
import { json, withConnector } from "@/lib/connector/http";
import { BODY_LIMITS } from "@/lib/connector/policy";

/** Audit relay: this bank's chain only, after={seq}, ≤ 500 records per page, oldest first. */
export async function GET(req: Request): Promise<Response> {
  await connection();
  return withConnector(req, "audit", BODY_LIMITS.get, async ({ connector, url }) => {
    const { after, limit } = parseAuditQuery(url);
    return json(await auditPage(connector, after, limit));
  });
}
