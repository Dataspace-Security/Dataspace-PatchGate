import { describe, expect, it } from "vitest";
import { APPROVAL_OFF_REASON, approvalSkipped, requiredApprovalsOf, transition, windowBypassGranted, type Actor, type CrSnapshot, type PriorApproval } from "./state-machine";

const BANK_A = "bank-a";
const BANK_B = "bank-b";

// Platform admin (our team) prepares; bank A admins approve; auditors (read-only) can do nothing.
const maker: Actor = { id: "u-maker", role: "ADMIN", tenantId: null };
const checker: Actor = { id: "u-checker", role: "ADMIN", tenantId: BANK_A };
const viewer: Actor = { id: "u-viewer", role: "AUDITOR", tenantId: BANK_A };

function cr(overrides: Partial<CrSnapshot> = {}): CrSnapshot {
  return { status: "DRAFT", createdById: maker.id, patchCount: 2, tenantId: BANK_A, requireBankApproval: true, ...overrides };
}

describe("change request state machine", () => {
  it("lets the maker submit a draft with patches", () => {
    expect(transition(cr(), "submit", maker)).toEqual({ ok: true, next: "PENDING_APPROVAL" });
  });

  it("refuses to submit an empty change request", () => {
    const r = transition(cr({ patchCount: 0 }), "submit", maker);
    expect(r.ok).toBe(false);
  });

  it("refuses submit by someone who is not the creator", () => {
    const r = transition(cr(), "submit", { id: "other", role: "ADMIN", tenantId: null });
    expect(r.ok).toBe(false);
  });

  it("lets a different approver approve", () => {
    const r = transition(cr({ status: "PENDING_APPROVAL" }), "approve", checker);
    expect(r).toEqual({ ok: true, next: "APPROVED" });
  });

  it("enforces maker-checker: creator cannot approve own request even as approver", () => {
    const makerApprover: Actor = { id: maker.id, role: "ADMIN", tenantId: BANK_A };
    const r = transition(cr({ status: "PENDING_APPROVAL" }), "approve", makerApprover);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toMatch(/maker-checker/i);
  });

  it("does not let auditors (or retired roles) make, approve, reject, deploy or cancel", () => {
    const pending = cr({ status: "PENDING_APPROVAL" });
    const platformAuditor: Actor = { id: "x", role: "AUDITOR", tenantId: null };
    for (const a of [viewer, platformAuditor, { id: "y", role: "APPROVER", tenantId: BANK_A } as Actor, { id: "z", role: "OPERATOR", tenantId: null } as Actor]) {
      expect(transition(pending, "approve", a).ok).toBe(false);
      expect(transition(pending, "reject", a).ok).toBe(false);
      expect(transition(cr({ status: "APPROVED" }), "deploy", a).ok).toBe(false);
      expect(transition(cr({ status: "APPROVED" }), "cancel", a).ok).toBe(false);
      expect(transition(cr({ createdById: a.id }), "submit", a).ok).toBe(false);
    }
  });

  it("lets an approver reject back", () => {
    const r = transition(cr({ status: "PENDING_APPROVAL" }), "reject", checker);
    expect(r).toEqual({ ok: true, next: "REJECTED" });
  });

  it("only deploys approved requests", () => {
    expect(transition(cr({ status: "APPROVED" }), "deploy", checker)).toEqual({
      ok: true,
      next: "DEPLOYING",
    });
    expect(transition(cr({ status: "PENDING_APPROVAL" }), "deploy", checker).ok).toBe(false);
    expect(transition(cr({ status: "DRAFT" }), "deploy", checker).ok).toBe(false);
  });

  it("rejects illegal transitions from terminal states", () => {
    expect(transition(cr({ status: "COMPLETED" }), "approve", checker).ok).toBe(false);
    expect(transition(cr({ status: "REJECTED" }), "deploy", checker).ok).toBe(false);
  });

  it("allows admin to cancel non-terminal requests", () => {
    const admin: Actor = { id: "a", role: "ADMIN", tenantId: null };
    expect(transition(cr({ status: "APPROVED" }), "cancel", admin)).toEqual({
      ok: true,
      next: "CANCELLED",
    });
    expect(transition(cr({ status: "COMPLETED" }), "cancel", admin).ok).toBe(false);
  });
});

describe("per-bank approval policy", () => {
  const pending = (o: Partial<CrSnapshot> = {}) => cr({ status: "PENDING_APPROVAL", ...o });
  const platformApprover: Actor = { id: "u-our-approver", role: "ADMIN", tenantId: null };
  const platformAdmin: Actor = { id: "u-our-admin", role: "ADMIN", tenantId: null };
  const bankAdmin: Actor = { id: "u-bank-admin", role: "ADMIN", tenantId: BANK_A };

  it("requireBankApproval: platform staff cannot approve or reject, even as approver/admin", () => {
    for (const actor of [platformApprover, platformAdmin]) {
      for (const action of ["approve", "reject"] as const) {
        const r = transition(pending(), action, actor);
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.error).toMatch(/bank approval required/i);
      }
    }
  });

  it("requireBankApproval: a bank approver or bank admin of THAT bank can decide", () => {
    expect(transition(pending(), "approve", checker)).toEqual({ ok: true, next: "APPROVED" });
    expect(transition(pending(), "approve", bankAdmin)).toEqual({ ok: true, next: "APPROVED" });
  });

  it("requireBankApproval off: our approver may act as checker for the bank", () => {
    expect(transition(pending({ requireBankApproval: false }), "approve", platformApprover)).toEqual({ ok: true, next: "APPROVED" });
  });

  it("maker-checker still applies to bank staff with the policy off", () => {
    const bankMaker: Actor = { id: "u-bank-maker", role: "ADMIN", tenantId: BANK_A };
    const r = transition(pending({ createdById: bankMaker.id, requireBankApproval: false }), "approve", bankMaker);
    expect(r.ok).toBe(false);
  });

  it("platform staff remain makers: they can submit, deploy and cancel for the bank", () => {
    expect(transition(cr(), "submit", maker).ok).toBe(true);
    expect(transition(cr({ status: "APPROVED" }), "deploy", maker).ok).toBe(true);
    expect(transition(cr({ status: "APPROVED" }), "cancel", maker).ok).toBe(true);
  });

  it("a user of another bank can do nothing at all on this bank's request", () => {
    const otherApprover: Actor = { id: "u-b-approver", role: "ADMIN", tenantId: BANK_B };
    const otherAdmin: Actor = { id: "u-b-admin", role: "ADMIN", tenantId: BANK_B };
    for (const policy of [true, false]) {
      expect(transition(pending({ requireBankApproval: policy }), "approve", otherApprover).ok).toBe(false);
      expect(transition(pending({ requireBankApproval: policy }), "reject", otherApprover).ok).toBe(false);
    }
    expect(transition(cr({ status: "APPROVED" }), "deploy", otherApprover).ok).toBe(false);
    expect(transition(cr({ status: "APPROVED" }), "cancel", otherAdmin).ok).toBe(false);
    const r = transition(cr({ createdById: otherAdmin.id }), "submit", otherAdmin);
    expect(r).toEqual({ ok: false, error: "Change request belongs to another bank" });
  });
});

describe("emergency changes (two distinct approvers)", () => {
  const bankApprover2: Actor = { id: "u-checker-2", role: "ADMIN", tenantId: BANK_A };
  const platformApprover: Actor = { id: "u-our-approver", role: "ADMIN", tenantId: null };
  const emergency = (o: Partial<CrSnapshot> = {}) =>
    cr({ status: "PENDING_APPROVAL", emergency: true, emergencyReason: "CVE exploited in the wild", requiredApprovals: 2, ...o });
  const approval = (a: Actor, deployNow = false): PriorApproval => ({ userId: a.id, approverBankId: a.tenantId, deployNow });

  it("submitting an emergency needs a reason", () => {
    expect(transition(cr({ emergency: true, emergencyReason: "  " }), "submit", maker)).toEqual({ ok: false, error: "An emergency change needs a reason" });
    expect(transition(cr({ emergency: true, emergencyReason: null }), "submit", maker).ok).toBe(false);
    expect(transition(cr({ emergency: true, emergencyReason: "outage" }), "submit", maker)).toEqual({ ok: true, next: "PENDING_APPROVAL" });
  });

  it("the first approval keeps the request pending; a second distinct approver approves it", () => {
    expect(transition(emergency(), "approve", checker)).toEqual({ ok: true, next: "PENDING_APPROVAL" });
    expect(transition(emergency({ approvals: [approval(checker)] }), "approve", bankApprover2)).toEqual({ ok: true, next: "APPROVED" });
  });

  it("the same approver cannot approve twice", () => {
    const r = transition(emergency({ approvals: [approval(checker)] }), "approve", checker);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toMatch(/different approver/i);
  });

  it("the maker is never one of the approvers (maker-checker still holds)", () => {
    const makerApprover: Actor = { id: maker.id, role: "ADMIN", tenantId: BANK_A };
    for (const approvals of [[], [approval(checker)]]) {
      const r = transition(emergency({ approvals }), "approve", makerApprover);
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.error).toMatch(/maker-checker/i);
    }
    // A (tampered) snapshot carrying a maker approval never completes.
    const tampered = emergency({ approvals: [{ userId: maker.id, approverBankId: BANK_A, deployNow: true }] });
    expect(transition(tampered, "approve", checker).ok).toBe(false);
  });

  it("an emergency needs two approvers even if the snapshot says one", () => {
    expect(requiredApprovalsOf({ emergency: true, requiredApprovals: 1 })).toBe(2);
    expect(requiredApprovalsOf({ emergency: false, requiredApprovals: undefined })).toBe(1);
    expect(transition(emergency({ requiredApprovals: 1 }), "approve", checker)).toEqual({ ok: true, next: "PENDING_APPROVAL" });
  });

  it("bank approval required: at least one approver from the bank, the other may be platform staff", () => {
    // platform first, bank second
    expect(transition(emergency(), "approve", platformApprover)).toEqual({ ok: true, next: "PENDING_APPROVAL" });
    expect(transition(emergency({ approvals: [approval(platformApprover)] }), "approve", checker)).toEqual({ ok: true, next: "APPROVED" });
    // bank first, platform second
    expect(transition(emergency({ approvals: [approval(checker)] }), "approve", platformApprover)).toEqual({ ok: true, next: "APPROVED" });
    // two platform approvers never complete it
    const other: Actor = { id: "u-our-approver-2", role: "ADMIN", tenantId: null };
    const r = transition(emergency({ approvals: [approval(platformApprover)] }), "approve", other);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toMatch(/at least one of the approvers must be from this bank/i);
    // policy off: two platform approvers are fine
    expect(transition(emergency({ requireBankApproval: false, approvals: [approval(platformApprover)] }), "approve", other)).toEqual({ ok: true, next: "APPROVED" });
  });

  it("large (non-emergency) requests above the target limit also need two approvers", () => {
    const big = cr({ status: "PENDING_APPROVAL", requiredApprovals: 2 });
    expect(transition(big, "approve", checker)).toEqual({ ok: true, next: "PENDING_APPROVAL" });
    expect(transition({ ...big, approvals: [approval(checker)] }, "approve", bankApprover2)).toEqual({ ok: true, next: "APPROVED" });
  });

  it("deploy now is only accepted on emergency changes", () => {
    const r = transition(cr({ status: "PENDING_APPROVAL" }), "approve", checker, { deployNow: true });
    expect(r.ok).toBe(false);
    expect(transition(emergency(), "approve", checker, { deployNow: true }).ok).toBe(true);
  });

  it("window bypass needs BOTH approvers to confirm deploy now", () => {
    expect(windowBypassGranted(true, [approval(checker, true), approval(bankApprover2, true)])).toBe(true);
    expect(windowBypassGranted(true, [approval(checker, true), approval(bankApprover2, false)])).toBe(false);
    expect(windowBypassGranted(true, [approval(checker, true)])).toBe(false);
    expect(windowBypassGranted(false, [approval(checker, true), approval(bankApprover2, true)])).toBe(false);
  });

  it("any eligible bank approver can still reject a half-approved emergency", () => {
    expect(transition(emergency({ approvals: [approval(checker)] }), "reject", bankApprover2)).toEqual({ ok: true, next: "REJECTED" });
  });
});

describe("approval expiry", () => {
  const expires = new Date("2026-10-20T00:00:00Z");
  const approved = cr({ status: "APPROVED", approvalExpiresAt: expires });
  it("deploys before the approval expires", () => {
    expect(transition(approved, "deploy", maker, { now: new Date("2026-10-19T23:59:00Z") })).toEqual({ ok: true, next: "DEPLOYING" });
  });
  it("refuses to deploy once the approval expired", () => {
    const r = transition(approved, "deploy", maker, { now: expires });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toMatch(/approval expired/i);
  });
  it("no expiry set = no limit", () => {
    expect(transition(cr({ status: "APPROVED", approvalExpiresAt: null }), "deploy", maker, { now: new Date("2030-01-01") }).ok).toBe(true);
  });
});

describe("approval switched OFF for the bank (requireBankApproval = false)", () => {
  const off = (overrides: Partial<CrSnapshot> = {}) => cr({ requireBankApproval: false, ...overrides });
  const bankAdmin: Actor = { id: "u-bank-admin", role: "ADMIN", tenantId: BANK_A };

  it("an admin's submit approves the request straight away (no second person)", () => {
    expect(approvalSkipped(off())).toBe(true);
    expect(transition(off(), "submit", maker)).toEqual({ ok: true, next: "APPROVED" });
    expect(transition(off({ createdById: bankAdmin.id }), "submit", bankAdmin)).toEqual({ ok: true, next: "APPROVED" });
  });

  it("the auto-approved request can then be deployed by its maker", () => {
    expect(transition(off({ status: "APPROVED" }), "deploy", maker)).toEqual({ ok: true, next: "DEPLOYING" });
  });

  it("emergency rules apply only while approval is ON: an emergency is auto-approved too (still needs a reason)", () => {
    expect(transition(off({ emergency: true, emergencyReason: "actively exploited zero-day" }), "submit", maker)).toEqual({ ok: true, next: "APPROVED" });
    expect(transition(off({ emergency: true, emergencyReason: null }), "submit", maker).ok).toBe(false);
  });

  it("auditors still cannot submit; empty requests are still refused", () => {
    expect(transition(off({ createdById: viewer.id }), "submit", viewer).ok).toBe(false);
    expect(transition(off({ patchCount: 0 }), "submit", maker).ok).toBe(false);
  });

  it("ON (default): submit only moves to PENDING_APPROVAL", () => {
    expect(approvalSkipped(cr())).toBe(false);
    expect(transition(cr(), "submit", maker)).toEqual({ ok: true, next: "PENDING_APPROVAL" });
  });

  it("records a readable policy reason", () => {
    expect(APPROVAL_OFF_REASON).toMatch(/approval is off/i);
  });
});
