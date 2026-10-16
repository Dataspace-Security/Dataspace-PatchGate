-- Approval on/off switch (2026-10-16): a bank ADMIN or platform ADMIN may switch "Approval required" off for a
-- bank (default stays ON). OFF = an admin's change request is approved on submit without a second person
-- (ChangeRequest.autoApproved, audit change_request.approval_skipped). The column keeps its meaning
-- "a bank admin must approve" while ON; the always-on CHECK of migration 20261016130000 is dropped.
ALTER TABLE "Tenant" DROP CONSTRAINT IF EXISTS "Tenant_requireBankApproval_always";
ALTER TABLE "ChangeRequest" ADD COLUMN IF NOT EXISTS "autoApproved" BOOLEAN NOT NULL DEFAULT false;
