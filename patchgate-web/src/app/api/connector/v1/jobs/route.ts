import { connection } from "next/server";
import { json, withConnector } from "@/lib/connector/http";
import { BODY_LIMITS, MAX_POLL_WAIT_SEC } from "@/lib/connector/policy";
import { pollJobs } from "@/lib/connector/queue";

/**
 * Long poll for signed jobs: GET /api/connector/v1/jobs?wait=N (N ≤ 25 s) → { jobs: SignedJob[] } (≤ 20).
 * Jobs are leased with FOR UPDATE SKIP LOCKED; re-delivery after the lease is byte-identical.
 */
export async function GET(req: Request): Promise<Response> {
  await connection();
  return withConnector(req, "jobs", BODY_LIMITS.get, async ({ connector, url }) => {
    const raw = url.searchParams.get("wait") ?? "0";
    const wait = /^\d{1,3}$/.test(raw) ? Math.min(MAX_POLL_WAIT_SEC, Number(raw)) : 0;
    const jobs = await pollJobs(connector.tenantId, connector.id, wait, req.signal);
    return json({ jobs });
  });
}
