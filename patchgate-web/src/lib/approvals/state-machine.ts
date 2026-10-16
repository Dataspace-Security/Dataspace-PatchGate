/**
 * Change-request lifecycle with maker-checker enforcement (ARCHITECTURE §5.3, ARCHITECTURE-HOSTED §5).
 * Pure: no I/O, so every rule is unit-testable.
 *
 * Roles (lib/auth/roles.ts): ADMIN makes (raises, submits, deploys) and checks; AUDITOR does nothing.
 *
 * Banks:
 *  - Every change request belongs to one bank (tenantId). A bank user (actor.tenantId set) can only act
 *    on their own bank's requests; platform staff (actor.tenantId null) may act for any bank.
 *  - `requireBankApproval` = the bank's "Approval required" switch (default ON; only an ADMIN can change it,
 *    audited + notified). ON: the checker MUST be an ADMIN of that bank. Our staff can then only be makers
 *    for that bank (or the SECOND approver, below). OFF: no second person — an ADMIN's submit moves the
 *    request straight to APPROVED (auto-approved, audited as change_request.approval_skipped).
 *  - Maker ≠ checker always (whenever a checker is involved).
 *
 * Multi-approver requests (approval ON only — emergency changes, or more targets than the bank's limit): `requiredApprovals`
 * = 2 DISTINCT admins, neither the maker. At least one of them must be an admin of the bank (the other may
 * be a second bank admin or a platform admin). An emergency may bypass the maintenance window only if BOTH
 * approvers explicitly confirmed "deploy now" (windowBypassGranted).
 */
import { canMake, canWrite, type Role } from "@/lib/auth/roles";

export type { Role } from "@/lib/auth/roles";

export type CrStatus =
  | "DRAFT"
  | "PENDING_APPROVAL"
  | "APPROVED"
  | "REJECTED"
  | "DEPLOYING"
  | "COMPLETED"
  | "PARTIAL"
  | "FAILED"
  | "CANCELLED";

export type CrAction = "submit" | "approve" | "reject" | "deploy" | "cancel";

export interface Actor {
  id: string;
  role: Role;
  /** null = platform staff (our team); otherwise the actor's bank */
  tenantId: string | null;
}

/** An approval already recorded on a multi-approver request. */
export interface PriorApproval {
  userId: string;
  /** Approver's bank at decision time (null = platform staff) */
  approverBankId: string | null;
  /** Emergency only: approver confirmed "deploy now" (bypass the maintenance window) */
  deployNow: boolean;
}

export interface CrSnapshot {
  status: CrStatus;
  createdById: string;
  patchCount: number;
  /** Owning bank */
  tenantId: string;
  /** Bank policy "Approval required": ON = a bank admin (never the maker) must approve; OFF = submit auto-approves */
  requireBankApproval: boolean;
  /** Emergency change (needs a reason and two distinct approvers) */
  emergency?: boolean;
  emergencyReason?: string | null;
  /** Distinct approvals needed (default 1; an emergency always needs 2) */
  requiredApprovals?: number;
  /** Approvals already recorded (multi-approver requests) */
  approvals?: readonly PriorApproval[];
  /** Approved requests must be started before this instant (bank approval-expiry policy) */
  approvalExpiresAt?: Date | null;
}

export interface TransitionOptions {
  /** Clock for the approval-expiry check (default: now) */
  now?: Date;
  /** approve only: the approver confirms "deploy now" (emergency window bypass) */
  deployNow?: boolean;
}

export type TransitionResult = { ok: true; next: CrStatus } | { ok: false; error: string };

const TERMINAL: ReadonlySet<CrStatus> = new Set([
  "REJECTED",
  "COMPLETED",
  "PARTIAL",
  "FAILED",
  "CANCELLED",
]);

/** Checkers are admins (whether bank or platform is decided per request in decideApprove / reject). */
const canDecide = (actor: Actor): boolean => canWrite(actor);

function fail(error: string): TransitionResult {
  return { ok: false, error };
}

export const EMERGENCY_APPROVALS = 2;

/** Distinct approvals the request needs: an emergency never fewer than two. */
export function requiredApprovalsOf(cr: Pick<CrSnapshot, "emergency" | "requiredApprovals">): number {
  const n = Math.max(1, Math.trunc(cr.requiredApprovals ?? 1));
  return cr.emergency ? Math.max(EMERGENCY_APPROVALS, n) : n;
}

/** Window bypass: an emergency whose (at least two) approvers ALL confirmed "deploy now". */
export function windowBypassGranted(emergency: boolean, approvals: readonly PriorApproval[]): boolean {
  return emergency && approvals.length >= EMERGENCY_APPROVALS && approvals.every((a) => a.deployNow);
}

/**
 * Approval OFF for the bank: a submitted request needs no second person and is approved on submit
 * (recorded as auto-approved). Emergency / two-approver rules apply only while approval is ON.
 */
export function approvalSkipped(cr: Pick<CrSnapshot, "requireBankApproval">): boolean {
  return !cr.requireBankApproval;
}

/** Human-readable policy reason recorded with an auto-approval (audit payload, UI). */
export const APPROVAL_OFF_REASON = "Approval is OFF for this bank (bank policy: approval not required) — no second person needed";

function decideApprove(cr: CrSnapshot, actor: Actor, opts: TransitionOptions): TransitionResult {
  const prior = cr.approvals ?? [];
  const required = requiredApprovalsOf(cr);
  if (prior.some((a) => a.userId === actor.id)) {
    return fail("You already approved this request; a second, different approver is required");
  }
  if (prior.some((a) => a.userId === cr.createdById)) {
    return fail("Maker-checker violation: the request carries an approval by its creator");
  }
  if (opts.deployNow && !cr.emergency) return fail("Only emergency changes can bypass the maintenance window");
  const final = prior.length + 1 >= required;
  if (cr.requireBankApproval) {
    if (required === 1 && actor.tenantId !== cr.tenantId) {
      return fail("Bank approval required: only an approver from this bank can decide this request");
    }
    const bankAlready = prior.some((a) => a.approverBankId === cr.tenantId);
    if (final && !bankAlready && actor.tenantId !== cr.tenantId) {
      return fail("Bank approval required: at least one of the approvers must be from this bank");
    }
  }
  return { ok: true, next: final ? "APPROVED" : "PENDING_APPROVAL" };
}

export function transition(cr: CrSnapshot, action: CrAction, actor: Actor, opts: TransitionOptions = {}): TransitionResult {
  // Defence in depth: services already load the request inside the actor's bank scope.
  if (actor.tenantId !== null && actor.tenantId !== cr.tenantId) {
    return fail("Change request belongs to another bank");
  }
  if (TERMINAL.has(cr.status)) {
    return fail(`Change request is ${cr.status} and can no longer change`);
  }

  switch (action) {
    case "submit":
      if (cr.status !== "DRAFT") return fail("Only drafts can be submitted");
      if (actor.id !== cr.createdById) return fail("Only the creator can submit");
      if (!canMake(actor)) return fail("Role cannot submit change requests");
      if (cr.patchCount === 0) return fail("Add at least one patch before submitting");
      if (cr.emergency && !cr.emergencyReason?.trim()) return fail("An emergency change needs a reason");
      return { ok: true, next: approvalSkipped(cr) ? "APPROVED" : "PENDING_APPROVAL" };

    case "approve":
    case "reject":
      if (cr.status !== "PENDING_APPROVAL") return fail("Request is not pending approval");
      if (!canDecide(actor)) return fail("Role cannot approve or reject");
      if (actor.id === cr.createdById) {
        return fail("Maker-checker violation: creator cannot decide own request");
      }
      if (action === "approve") return decideApprove(cr, actor, opts);
      if (cr.requireBankApproval && actor.tenantId !== cr.tenantId) {
        return fail("Bank approval required: only an approver from this bank can decide this request");
      }
      return { ok: true, next: "REJECTED" };

    case "deploy":
      if (cr.status !== "APPROVED") return fail("Only approved requests can be deployed");
      if (!canMake(actor)) return fail("Role cannot start deployments");
      if (cr.approvalExpiresAt && (opts.now ?? new Date()).getTime() >= cr.approvalExpiresAt.getTime()) {
        return fail(`Approval expired on ${cr.approvalExpiresAt.toISOString().slice(0, 16).replace("T", " ")} UTC; cancel it and raise a new request`);
      }
      return { ok: true, next: "DEPLOYING" };

    case "cancel":
      if (!canWrite(actor)) return fail("Only the creator or an admin can cancel");
      // While deploying, cancel = stop the rollout: PCs not started yet are skipped, installs already handed to
      // the site finish; the request then closes normally (FAILED / PARTIAL) once nothing is in flight.
      if (cr.status === "DEPLOYING") return { ok: true, next: "DEPLOYING" };
      return { ok: true, next: "CANCELLED" };
  }
}
