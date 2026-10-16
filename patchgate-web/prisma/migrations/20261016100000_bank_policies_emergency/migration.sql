-- Bank self-service policies, emergency changes and account security policy.
--  1. Tenant: timezone (window previews), default reboot policy, approval expiry (days), target limit per CR.
--  2. Ring.rebootPolicy: per-ring override of the bank default for new change requests.
--  3. ChangeRequest: emergency (+ reason), reboot policy, required approvals, approval expiry, window bypass.
--  4. ChangeRequestApproval: one row per approver decision (tenant-owned, FORCED row-level security);
--     a trigger refuses an approval by the request's maker (maker ≠ checker, defence in depth).
--  5. SecurityPolicy: platform-wide password max age / inactivity disable / session cap (no tenant rows).
-- Idempotent where practical (IF NOT EXISTS), like the earlier migrations.

-- 1. Tenant ---------------------------------------------------------------------------------------
ALTER TABLE "Tenant" ADD COLUMN IF NOT EXISTS "timezone" TEXT NOT NULL DEFAULT 'Asia/Kolkata';
ALTER TABLE "Tenant" ADD COLUMN IF NOT EXISTS "defaultRebootPolicy" "RebootPolicy" NOT NULL DEFAULT 'REQUIRED';
ALTER TABLE "Tenant" ADD COLUMN IF NOT EXISTS "approvalExpiryDays" INTEGER NOT NULL DEFAULT 14;
ALTER TABLE "Tenant" ADD COLUMN IF NOT EXISTS "maxTargetsPerCr" INTEGER NOT NULL DEFAULT 0;
DO $$ BEGIN
  ALTER TABLE "Tenant" ADD CONSTRAINT "Tenant_approvalExpiryDays_check" CHECK ("approvalExpiryDays" BETWEEN 0 AND 365);
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN
  ALTER TABLE "Tenant" ADD CONSTRAINT "Tenant_maxTargetsPerCr_check" CHECK ("maxTargetsPerCr" BETWEEN 0 AND 1000000);
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- 2. Ring -----------------------------------------------------------------------------------------
ALTER TABLE "Ring" ADD COLUMN IF NOT EXISTS "rebootPolicy" "RebootPolicy";

-- 3. ChangeRequest --------------------------------------------------------------------------------
ALTER TABLE "ChangeRequest" ADD COLUMN IF NOT EXISTS "emergency" BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE "ChangeRequest" ADD COLUMN IF NOT EXISTS "emergencyReason" TEXT;
ALTER TABLE "ChangeRequest" ADD COLUMN IF NOT EXISTS "rebootPolicy" "RebootPolicy";
ALTER TABLE "ChangeRequest" ADD COLUMN IF NOT EXISTS "requiredApprovals" INTEGER NOT NULL DEFAULT 1;
ALTER TABLE "ChangeRequest" ADD COLUMN IF NOT EXISTS "approvalExpiresAt" TIMESTAMP(3);
ALTER TABLE "ChangeRequest" ADD COLUMN IF NOT EXISTS "windowBypass" BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE "ChangeRequest" ADD COLUMN IF NOT EXISTS "bypassedWindowId" TEXT;
DO $$ BEGIN
  ALTER TABLE "ChangeRequest" ADD CONSTRAINT "ChangeRequest_requiredApprovals_check" CHECK ("requiredApprovals" BETWEEN 1 AND 2);
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
-- An emergency always carries its reason; only an emergency may bypass the window.
DO $$ BEGIN
  ALTER TABLE "ChangeRequest" ADD CONSTRAINT "ChangeRequest_emergency_reason_check"
    CHECK (NOT "emergency" OR ("emergencyReason" IS NOT NULL AND length(btrim("emergencyReason")) > 0));
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN
  ALTER TABLE "ChangeRequest" ADD CONSTRAINT "ChangeRequest_window_bypass_check"
    CHECK (NOT "windowBypass" OR ("emergency" AND "requiredApprovals" = 2));
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- 4. ChangeRequestApproval ------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS "ChangeRequestApproval" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "changeRequestId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "userUpn" TEXT NOT NULL,
    "userName" TEXT NOT NULL,
    "approverBankId" TEXT,
    "deployNow" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "ChangeRequestApproval_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX IF NOT EXISTS "ChangeRequestApproval_changeRequestId_userId_key" ON "ChangeRequestApproval"("changeRequestId", "userId");
CREATE INDEX IF NOT EXISTS "ChangeRequestApproval_tenantId_idx" ON "ChangeRequestApproval"("tenantId");
DO $$ BEGIN
  ALTER TABLE "ChangeRequestApproval" ADD CONSTRAINT "ChangeRequestApproval_changeRequestId_fkey"
    FOREIGN KEY ("changeRequestId") REFERENCES "ChangeRequest"("id") ON DELETE CASCADE ON UPDATE CASCADE;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN
  ALTER TABLE "ChangeRequestApproval" ADD CONSTRAINT "ChangeRequestApproval_tenantId_fkey"
    FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

ALTER TABLE "ChangeRequestApproval" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "ChangeRequestApproval" FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON "ChangeRequestApproval";
CREATE POLICY tenant_isolation ON "ChangeRequestApproval"
  USING ("tenantId" = current_setting('app.tenant_id', true) OR current_setting('app.scope', true) = 'platform')
  WITH CHECK ("tenantId" = current_setting('app.tenant_id', true) OR current_setting('app.scope', true) = 'platform');
GRANT SELECT, INSERT, UPDATE, DELETE ON "ChangeRequestApproval" TO patchgate_tenant;

-- Maker ≠ checker at the database level, and the approval must be for a request of the same bank.
CREATE OR REPLACE FUNCTION patchgate_cr_approval_guard() RETURNS trigger AS $$
DECLARE
  maker TEXT;
  owner_bank TEXT;
BEGIN
  SELECT c."createdById", c."tenantId" INTO maker, owner_bank FROM "ChangeRequest" c WHERE c."id" = NEW."changeRequestId";
  IF maker IS NULL THEN
    RAISE EXCEPTION 'change request % not found', NEW."changeRequestId";
  END IF;
  IF owner_bank IS DISTINCT FROM NEW."tenantId" THEN
    RAISE EXCEPTION 'approval bank does not match the change request';
  END IF;
  IF maker = NEW."userId" THEN
    RAISE EXCEPTION 'maker-checker violation: the maker cannot approve their own change request';
  END IF;
  RETURN NEW;
END
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS "ChangeRequestApproval_guard" ON "ChangeRequestApproval";
CREATE TRIGGER "ChangeRequestApproval_guard"
  BEFORE INSERT OR UPDATE ON "ChangeRequestApproval"
  FOR EACH ROW EXECUTE FUNCTION patchgate_cr_approval_guard();

-- 5. SecurityPolicy (platform data, no tenant rows: no RLS) ------------------------------------------
CREATE TABLE IF NOT EXISTS "SecurityPolicy" (
    "id" TEXT NOT NULL DEFAULT 'platform',
    "passwordMaxAgeDays" INTEGER NOT NULL DEFAULT 0,
    "inactivityDisableDays" INTEGER NOT NULL DEFAULT 90,
    "maxSessionsPerUser" INTEGER NOT NULL DEFAULT 0,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "updatedBy" TEXT,
    CONSTRAINT "SecurityPolicy_pkey" PRIMARY KEY ("id")
);
DO $$ BEGIN
  ALTER TABLE "SecurityPolicy" ADD CONSTRAINT "SecurityPolicy_singleton_check" CHECK ("id" = 'platform');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN
  ALTER TABLE "SecurityPolicy" ADD CONSTRAINT "SecurityPolicy_ranges_check" CHECK (
    "passwordMaxAgeDays" BETWEEN 0 AND 3650 AND "inactivityDisableDays" BETWEEN 0 AND 3650 AND "maxSessionsPerUser" BETWEEN 0 AND 100);
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
GRANT SELECT, INSERT, UPDATE, DELETE ON "SecurityPolicy" TO patchgate_tenant;
