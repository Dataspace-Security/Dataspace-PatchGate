import "server-only";
import { z } from "zod";
import { appendAudit } from "@/lib/audit/service";
import { AuthError, type SessionUser } from "@/lib/auth/session";
import { DomainError } from "@/lib/errors";
import { canActForTenant, withTenant, type Tx } from "@/lib/tenancy";
import { approvalExpiryFrom, requiredApprovalsFor, resolveRebootPolicy } from "@/lib/policies/approval-policy";
import { APPROVAL_OFF_REASON, transition, windowBypassGranted, type CrAction, type CrSnapshot } from "./state-machine";
import { recordApproval } from "./approval-record";
import { eligibilityErrors } from "./eligibility";
import { enabledAppIds, toEligible, requiresOfflineWindowsScan } from "./load-eligible";
import { notifyChangeRequestAction } from "@/lib/notify/enqueue";
import { AuditBuffer, stopNotStarted } from "@/lib/deploy/connector-state";
import { lockConnectorPumps } from "@/lib/deploy/connector-deploy";

export const createChangeRequestSchema = z.object({
  title: z.string().trim().min(3).max(200),
  ticketRef: z.string().trim().max(64).optional(),
  ringId: z.string().min(1),
  windowId: z.string().min(1).optional(),
  patchIds: z.array(z.string().min(1)).min(1).max(500),
  // Optional: the draft options can also be set later on the request page (see emergency.ts).
  emergency: z.boolean().optional(),
  emergencyReason: z.string().trim().min(10, "describe the emergency (at least 10 characters)").max(500).optional(),
  rebootPolicy: z.enum(["NEVER", "REQUIRED", "ALWAYS"]).optional(),
}).refine((v) => !v.emergency || !!v.emergencyReason, { path: ["emergencyReason"], message: "an emergency change needs a reason" });
export type CreateChangeRequestInput = z.infer<typeof createChangeRequestSchema>;

export const decisionSchema = z.object({
  reason: z.string().trim().max(500).optional(),
  /** approve only (emergency): this approver confirms deploying immediately, outside the maintenance window */
  deployNow: z.boolean().optional(),
});

/** Audit action of a lifecycle step: emergency changes get their own actions (SIEM alerting). */
export function crAuditAction(action: CrAction, emergency: boolean): string {
  return emergency ? `change_request.emergency_${action}` : `change_request.${action}`;
}

/** Bank users may only ever act for their own bank (the request layer already resolves it; this is depth). */
export function assertCanActFor(user: SessionUser, tenantId: string): void {
  if (!canActForTenant(user, tenantId)) throw new AuthError("Not allowed for this bank", 403);
}

/** Load the snapshot the state machine needs — only if the request belongs to `tenantId`. */
export async function loadSnapshot(tx: Tx, tenantId: string, crId: string): Promise<CrSnapshot> {
  const cr = await tx.changeRequest.findFirst({
    where: { id: crId, tenantId },
    select: {
      status: true,
      createdById: true,
      tenantId: true,
      emergency: true,
      emergencyReason: true,
      requiredApprovals: true,
      approvalExpiresAt: true,
      tenant: { select: { requireBankApproval: true } },
      approvals: { select: { userId: true, approverBankId: true, deployNow: true }, orderBy: { createdAt: "asc" } },
      _count: { select: { patches: true } },
    },
  });
  if (!cr) throw new DomainError("Change request not found", 404);
  return {
    status: cr.status,
    createdById: cr.createdById,
    patchCount: cr._count.patches,
    tenantId: cr.tenantId,
    requireBankApproval: cr.tenant.requireBankApproval,
    emergency: cr.emergency,
    emergencyReason: cr.emergencyReason,
    requiredApprovals: cr.requiredApprovals,
    approvalExpiresAt: cr.approvalExpiresAt,
    // Only approvals of the current approval round count (a new submit clears them).
    approvals: cr.status === "PENDING_APPROVAL" || cr.status === "APPROVED" ? cr.approvals : [],
  };
}

/** Create a DRAFT change request for one bank (ring + window must be that bank's). */
export async function createChangeRequest(user: SessionUser, tenantId: string, input: CreateChangeRequestInput) {
  assertCanActFor(user, tenantId);
  const patchIds = [...new Set(input.patchIds)];

  return withTenant(tenantId, async (tx) => {
    const ring = await tx.ring.findFirst({
      where: { id: input.ringId, tenantId },
      select: { id: true, rebootPolicy: true, tenant: { select: { defaultRebootPolicy: true } } },
    });
    if (!ring) throw new DomainError("Ring not found", 404);
    const rebootPolicy = resolveRebootPolicy(input.rebootPolicy, ring.rebootPolicy, ring.tenant.defaultRebootPolicy);
    const emergency = input.emergency === true;
    if (input.windowId) {
      const w = await tx.maintenanceWindow.findFirst({ where: { id: input.windowId, tenantId } });
      if (!w || w.ringId !== input.ringId) {
        throw new DomainError("Maintenance window does not belong to this ring", 400);
      }
    }

    // Patch catalog is shared across banks; third-party packages additionally need the bank's opt-in.
    const patches = await tx.patch.findMany({
      where: { id: { in: patchIds } },
      include: { appVersion: { include: { app: true } } },
    });
    if (patches.length !== patchIds.length) throw new DomainError("One or more patches not found", 404);

    const errors = eligibilityErrors(await toEligible(patches, await enabledAppIds(tx, tenantId), tx, { requireOfflineScan: await requiresOfflineWindowsScan(tx, tenantId) }), new Date());
    if (errors.length > 0) throw new DomainError(errors.join("; "), 422);

    const cr = await tx.changeRequest.create({
      data: {
        tenantId,
        title: input.title,
        ticketRef: input.ticketRef,
        ringId: input.ringId,
        windowId: input.windowId,
        createdById: user.id,
        rebootPolicy,
        emergency,
        emergencyReason: emergency ? input.emergencyReason : null,
        requiredApprovals: emergency ? 2 : 1,
        patches: { create: patchIds.map((patchId) => ({ patchId })) },
      },
    });
    await appendAudit(
      {
        tenantId,
        actor: user.upn,
        action: "change_request.create",
        entity: "ChangeRequest",
        entityId: cr.id,
        payload: { patchIds, ringId: input.ringId, ticketRef: input.ticketRef ?? null, rebootPolicy, emergency },
      },
      tx,
    );
    if (emergency) {
      await appendAudit(
        { tenantId, actor: user.upn, action: "change_request.emergency_marked", entity: "ChangeRequest", entityId: cr.id, payload: { reason: input.emergencyReason ?? null } },
        tx,
      );
    }
    return cr;
  });
}

/**
 * Snapshot the target endpoints (the ring's PCs right now) when a request is submitted: the approver
 * approves exactly this set (count shown on the request), and deployments only ever go to it — adding PCs
 * to the ring after approval does not widen the request; that needs a new request and a new approval.
 */
async function snapshotTargets(tx: Tx, tenantId: string, crId: string): Promise<number> {
  const cr = await tx.changeRequest.findFirst({ where: { id: crId, tenantId }, select: { ringId: true } });
  if (!cr) throw new DomainError("Change request not found", 404);
  await tx.changeRequestTarget.deleteMany({ where: { changeRequestId: crId, tenantId } });
  const inserted = await tx.$executeRaw`
    INSERT INTO "ChangeRequestTarget" ("changeRequestId", "endpointId", "tenantId")
    SELECT ${crId}, e."id", e."tenantId" FROM "Endpoint" e WHERE e."tenantId" = ${tenantId} AND e."ringId" = ${cr.ringId}`;
  await tx.changeRequest.updateMany({ where: { id: crId, tenantId }, data: { targetCount: inserted } });
  return inserted;
}

const STAMP: Partial<Record<CrAction, "submittedAt" | "decidedAt">> = {
  submit: "submittedAt",
  approve: "decidedAt",
  reject: "decidedAt",
};

/**
 * Apply a lifecycle action atomically, guarded by the state machine (maker-checker + bank policy)
 * and an optimistic status check. A request of another bank is reported as not found.
 */
export async function applyAction(
  user: SessionUser,
  tenantId: string,
  crId: string,
  action: Exclude<CrAction, "deploy">,
  reason?: string,
  opts: { deployNow?: boolean } = {},
) {
  assertCanActFor(user, tenantId);
  return withTenant(tenantId, async (tx) => {
    // Row lock: two approvers deciding at once are serialised (the second sees the first approval).
    await tx.$queryRaw`SELECT 1 FROM "ChangeRequest" WHERE "id" = ${crId} AND "tenantId" = ${tenantId} FOR UPDATE`;
    const cr = await loadSnapshot(tx, tenantId, crId);
    const now = new Date();
    const emergency = cr.emergency === true;

    const result = transition(cr, action, user, { now, deployNow: opts.deployNow === true });
    if (!result.ok) throw new DomainError(result.error, 409);
    // Stop rollout: hold the bank's connector pumps first, so nothing is claimed or enqueued while we stop.
    const stopping = action === "cancel" && cr.status === "DEPLOYING";
    const viaConnector = stopping ? (await lockConnectorPumps(tx, tenantId)) > 0 : false;
    if (action === "submit") {
      // Refuse before maker + checker spend time on a request PatchGate cannot deliver.
      const rows = await tx.changeRequestPatch.findMany({ where: { changeRequestId: crId }, select: { patch: { include: { appVersion: { include: { app: true } } } } } });
      const eligible = await toEligible(rows.map((r) => r.patch), await enabledAppIds(tx, tenantId), tx, { requireOfflineScan: await requiresOfflineWindowsScan(tx, tenantId) });
      const errors = eligibilityErrors(eligible, now);
      if (errors.length > 0) throw new DomainError(errors.join("; "), 422);
    }

    const approval = action === "approve" ? await recordApproval(tx, tenantId, crId, user, emergency && opts.deployNow === true) : null;
    // Approval OFF for the bank: the submit itself approves (no second person; see state-machine.ts).
    const autoApproved = action === "submit" && result.next === "APPROVED";
    const finalApproval = (action === "approve" && result.next === "APPROVED") || autoApproved;
    const policy =
      finalApproval || action === "submit"
        ? await tx.tenant.findUnique({ where: { id: tenantId }, select: { approvalExpiryDays: true, maxTargetsPerCr: true } })
        : null;
    // Emergency window bypass only when EVERY approver confirmed "deploy now".
    const bypass = finalApproval && !autoApproved && windowBypassGranted(emergency, approval?.all ?? []);
    const bypassedWindowId = bypass ? ((await tx.changeRequest.findFirst({ where: { id: crId, tenantId }, select: { windowId: true } }))?.windowId ?? null) : null;
    const approvalExpiresAt = finalApproval ? approvalExpiryFrom(now, policy?.approvalExpiryDays ?? 0) : null;

    const stamp = result.next === cr.status ? undefined : STAMP[action];
    // updateMany with status guard = no lost update if two approvers click at once
    const { count } = await tx.changeRequest.updateMany({
      where: { id: crId, tenantId, status: cr.status },
      data: {
        status: result.next,
        ...(stamp ? { [stamp]: now } : {}),
        ...(action === "submit" ? { autoApproved } : {}),
        ...(autoApproved ? { decidedAt: now, approvedById: null, approvalExpiresAt } : finalApproval ? { approvedById: user.id, approvalExpiresAt } : {}),
        // The pipeline treats "no window" as "deploy as soon as started"; the original window is kept for the record.
        ...(bypass ? { windowBypass: true, bypassedWindowId, windowId: null } : {}),
        ...(action === "reject" ? { rejectReason: reason ?? null } : {}),
      },
    });
    if (count !== 1) throw new DomainError("Change request was modified concurrently", 409);
    // Cancel while deploying = stop the rollout (state-machine.ts): skip what has not started, let in-flight finish.
    let rolloutStop: { stopped: number; cancelledJobs: number } | undefined;
    if (stopping) {
      const audits = new AuditBuffer();
      rolloutStop = await stopNotStarted(tx, tenantId, crId, `rollout stopped by ${user.upn}; not started`, `rollout stopped by ${user.upn}`, now, audits, {
        sending: viaConnector,
      });
      if (rolloutStop.stopped + rolloutStop.cancelledJobs === 0) {
        throw new DomainError("Nothing left to stop: every PC of this rollout has already started", 409);
      }
      await audits.flush(tx);
    }
    // The approval is for the snapshotted PCs: record how many in both the submit and the decision.
    let targets: number | undefined;
    if (action === "submit") {
      await tx.changeRequestApproval.deleteMany({ where: { changeRequestId: crId, tenantId } });
      targets = await snapshotTargets(tx, tenantId, crId);
      const requiredApprovals = requiredApprovalsFor({ emergency, targetCount: targets, maxTargetsPerCr: policy?.maxTargetsPerCr ?? 0 });
      if (!autoApproved) await tx.changeRequest.updateMany({ where: { id: crId, tenantId }, data: { requiredApprovals, approvalExpiresAt: null } });
    } else if (action === "approve") {
      targets = (await tx.changeRequest.findFirst({ where: { id: crId, tenantId }, select: { targetCount: true } }))?.targetCount ?? undefined;
    }

    await appendAudit(
      {
        tenantId,
        actor: user.upn,
        action: crAuditAction(action, emergency),
        entity: "ChangeRequest",
        entityId: crId,
        payload: {
          from: cr.status,
          to: result.next,
          reason: reason ?? null,
          actorBank: user.tenantId ?? "platform",
          ...(targets !== undefined ? { targetEndpoints: targets } : {}),
          ...(approval ? { approvalNo: approval.all.length, deployNow: approval.row.deployNow } : {}),
          ...(approvalExpiresAt ? { approvalExpiresAt: approvalExpiresAt.toISOString() } : {}),
          ...(rolloutStop ? { rolloutStopped: true, stoppedDeployments: rolloutStop.stopped, cancelledJobs: rolloutStop.cancelledJobs } : {}),
        },
      },
      tx,
    );
    if (autoApproved) {
      await appendAudit(
        {
          tenantId,
          actor: user.upn,
          action: "change_request.approval_skipped",
          entity: "ChangeRequest",
          entityId: crId,
          payload: {
            reason: APPROVAL_OFF_REASON,
            policy: { requireBankApproval: false },
            maker: user.upn,
            actorBank: user.tenantId ?? "platform",
            emergency,
            ...(targets !== undefined ? { targetEndpoints: targets } : {}),
            ...(approvalExpiresAt ? { approvalExpiresAt: approvalExpiresAt.toISOString() } : {}),
          },
        },
        tx,
      );
    }
    if (bypass) {
      await appendAudit(
        {
          tenantId,
          actor: user.upn,
          action: "change_request.emergency_window_bypass",
          entity: "ChangeRequest",
          entityId: crId,
          payload: { bypassedWindowId, confirmedBy: approval?.all.map((a) => a.userUpn) ?? [] },
        },
        tx,
      );
    }
    // A partial approval (first of two) is not "approved" yet: no approval notification for it.
    if (!(action === "approve" && !finalApproval)) await notifyChangeRequestAction(tx, tenantId, crId, action, user, reason);
    return { id: crId, status: result.next, approvals: approval?.all.length ?? null, windowBypass: bypass, autoApproved };
  });
}
