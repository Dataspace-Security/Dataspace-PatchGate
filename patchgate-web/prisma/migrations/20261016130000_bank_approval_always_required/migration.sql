-- Platform rule (2026-10-16): every change request needs at least ONE approver from the bank itself.
-- A bank administrator (or a platform administrator) can no longer turn this off; the database refuses it.
UPDATE "Tenant" SET "requireBankApproval" = true WHERE "requireBankApproval" = false;
ALTER TABLE "Tenant" ADD CONSTRAINT "Tenant_requireBankApproval_always" CHECK ("requireBankApproval" = true);
