import { Alert } from "./ui";

export const APPROVAL_OFF_TEXT = "Approval is OFF for this bank — requests deploy without a second person";

/** Amber note shown on the dashboard and change-request pages while the bank's approval is switched off. */
export function ApprovalOffNote({ approvalRequired }: { approvalRequired: boolean }) {
  if (approvalRequired) return null;
  return (
    <div data-testid="approval-off-note">
      <Alert tone="warn">
        <b>{APPROVAL_OFF_TEXT}.</b> Submitted requests are auto-approved (recorded in the audit log). An admin can switch approval back on in
        Settings → Approval policy.
      </Alert>
    </div>
  );
}
