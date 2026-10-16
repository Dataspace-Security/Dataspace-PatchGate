import { connection } from "next/server";
import { redeemEnrollment } from "@/lib/connector/enroll";
import { errorResponse, json, parseJsonBody, readBodyCapped } from "@/lib/connector/http";
import { BODY_LIMITS } from "@/lib/connector/policy";

/**
 * Connector enrolment (unsigned: the connector has no identity yet). One-time code + proof of possession
 * of the connector's locally generated Ed25519 key → { connectorId, tenantId, name, jobSigningPublicKey }.
 * Bad, used or expired code / bad proof → 403. Rate limited per address in src/proxy.ts.
 */
export async function POST(req: Request): Promise<Response> {
  await connection();
  try {
    const body = parseJsonBody(await readBodyCapped(req, BODY_LIMITS.enroll));
    return json(await redeemEnrollment(body), 201);
  } catch (err: unknown) {
    return errorResponse(err, "enroll");
  }
}
