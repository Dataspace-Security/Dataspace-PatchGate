import "server-only";
import { appendAudit } from "@/lib/audit/service";
import { DomainError } from "@/lib/errors";
import type { SessionUser } from "@/lib/auth/session";
import { transition } from "@/lib/approvals/state-machine";
import { eligibilityErrors } from "@/lib/approvals/eligibility";
import { enabledAppIds, toEligible } from "@/lib/approvals/load-eligible";
import { assertCanActFor } from "@/lib/approvals/service";
import { withTenant } from "@/lib/tenancy";
import { deployDeadlineFrom } from "./deadline";

const START_TX_TIMEOUT_MS = 120_000;

/**
 * Queue an approved change request of one bank. No Tactical calls happen here — the worker
 * (/api/worker/tick) pushes to endpoints inside the maintenance window.
 * All checks run BEFORE the status flips, so a bad request can never get stuck in DEPLOYING.
 * Targets = the endpoints snapshotted when the request was submitted (what the approver approved), NOT
 * the ring as it is now. The deployments are created with ONE set-based INSERT (50k PCs per bank).
 */
export async function startDeployment(user: SessionUser, tenantId: string, crId: string) {
  assertCanActFor(user, tenantId);
  return withTenant(tenantId, async (tx) => {
    const cr = await tx.changeRequest.findFirst({
      where: { id: crId, tenantId },
      include: {
        tenant: { select: { requireBankApproval: true } },
        patches: { include: { patch: { include: { appVersion: { include: { app: true } } } } } },
      },
    });
    if (!cr) throw new DomainError("Change request not found", 404);

    const t = transition(
      {
        status: cr.status,
        createdById: cr.createdById,
        patchCount: cr.patches.length,
        tenantId: cr.tenantId,
        requireBankApproval: cr.tenant.requireBankApproval,
        approvalExpiresAt: cr.approvalExpiresAt, // bank policy: approval must be used within N days
      },
      "deploy",
      user,
    );
    if (!t.ok) throw new DomainError(t.error, 409);

    const eligible = await toEligible(cr.patches.map((p) => p.patch), await enabledAppIds(tx, tenantId), tx);
    const errors = eligibilityErrors(eligible, new Date());
    if (errors.length > 0) throw new DomainError(errors.join("; "), 409);

    if (cr.targetCount === null) throw new DomainError("Change request has no approved target list; resubmit it for approval", 409);
    const targets = await tx.changeRequestTarget.count({ where: { changeRequestId: crId, tenantId } });
    if (targets === 0) throw new DomainError("Target ring has no endpoints", 409);

    const now = new Date();
    const deadline = deployDeadlineFrom(now);
    const { count } = await tx.changeRequest.updateMany({
      where: { id: crId, tenantId, status: "APPROVED" },
      data: { status: "DEPLOYING", deployDeadlineAt: deadline },
    });
    if (count !== 1) throw new DomainError("Change request was modified concurrently", 409);

    const queued = await tx.$executeRaw`
      INSERT INTO "Deployment" ("id", "tenantId", "changeRequestId", "endpointId", "connectorId", "status", "attempts", "targetGuids", "nextAttemptAt")
      SELECT 'dpl_' || md5(${crId} || ':' || t."endpointId"), ${tenantId}, ${crId}, t."endpointId", e."connectorId", 'QUEUED', 0, ARRAY[]::text[], ${now}
        FROM "ChangeRequestTarget" t
        JOIN "Endpoint" e ON e."id" = t."endpointId" AND e."tenantId" = ${tenantId}
       WHERE t."changeRequestId" = ${crId} AND t."tenantId" = ${tenantId}
      ON CONFLICT DO NOTHING`;

    await appendAudit(
      {
        tenantId,
        actor: user.upn,
        action: "change_request.deploy",
        entity: "ChangeRequest",
        entityId: crId,
        payload: { endpoints: queued, approvedTargets: cr.targetCount, patches: cr.patches.length, deadline: deadline.toISOString() },
      },
      tx,
    );

    return { id: crId, status: "DEPLOYING" as const, queued };
  }, { timeoutMs: START_TX_TIMEOUT_MS });
}
