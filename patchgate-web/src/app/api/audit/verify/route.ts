import { z } from "zod";
import { getCurrentUser, requireReader, requireSameOrigin } from "@/lib/auth/session";
import { handle, ok } from "@/lib/api/response";
import { appendAudit, verifyAuditLogCached, verifySiemAnchor } from "@/lib/audit/service";
import { auditExportStatus } from "@/lib/audit/export";
import { resolveAuditChain } from "@/lib/audit/chain-scope";

/** Verify ONE chain: the caller's bank, or (our staff, `?chain=platform`) the platform chain. */
export async function GET(req: Request): Promise<Response> {
  return handle(async () => {
    const user = await getCurrentUser();
    requireReader(user);
    const { tenantId } = await resolveAuditChain(user, new URL(req.url).searchParams.get("chain"));
    const [verification, exportStatus] = await Promise.all([verifyAuditLogCached(tenantId), auditExportStatus(tenantId)]);
    return ok({ verification, exportStatus });
  });
}

const anchorSchema = z.object({
  seq: z.string().regex(/^\d{1,18}$/), // always fits in a signed 64-bit integer
  hash: z.string().regex(/^[a-f0-9]{64}$/),
  chain: z.literal("platform").optional(),
});

/**
 * Auditor pastes an ANCHOR record (seq + hash) taken from the SIEM; it is checked against their chain only.
 * A read-only check (it changes no data, only records that the check happened), so AUDITORs may run it —
 * one of the two deliberate POST exceptions for auditors besides their own account (see docs/RUNBOOK.md roles).
 */
export async function POST(req: Request): Promise<Response> {
  return handle(async () => {
    requireSameOrigin(req);
    const user = await getCurrentUser();
    requireReader(user);
    const a = anchorSchema.parse(await req.json());
    const { tenantId } = await resolveAuditChain(user, a.chain);
    const result = await verifySiemAnchor(tenantId, BigInt(a.seq), a.hash);
    await appendAudit({
      tenantId,
      actor: user.upn,
      action: "audit.verify_siem_anchor",
      entity: "AuditEvent",
      entityId: a.seq,
      payload: { match: result.match },
    });
    return ok(result);
  });
}
