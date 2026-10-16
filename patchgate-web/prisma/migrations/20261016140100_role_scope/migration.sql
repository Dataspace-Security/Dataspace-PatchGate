-- Role model (2026-10-16): the same two roles for our team (tenantId NULL) and inside every bank.
--   ADMIN   = does everything in its scope; a bank ADMIN is also the bank's checker (approver).
--   AUDITOR = read-only in its scope (platform: all banks; bank: its own bank).
-- Mapping of the retired roles (never more rights across scopes; bank approvers already decided requests):
--   platform OPERATOR / APPROVER / VIEWER -> AUDITOR
--   bank     APPROVER                     -> ADMIN   (bank admins are now the bank's checkers)
--   bank     OPERATOR / VIEWER            -> AUDITOR
UPDATE "User" SET "role" = 'AUDITOR' WHERE "tenantId" IS NULL AND "role" IN ('OPERATOR', 'APPROVER', 'VIEWER');
UPDATE "User" SET "role" = 'ADMIN' WHERE "tenantId" IS NOT NULL AND "role" = 'APPROVER';
UPDATE "User" SET "role" = 'AUDITOR' WHERE "tenantId" IS NOT NULL AND "role" IN ('OPERATOR', 'VIEWER');

ALTER TABLE "User" ALTER COLUMN "role" SET DEFAULT 'AUDITOR';

-- The retired values stay in the enum (Postgres cannot drop enum values) but can never be stored again.
ALTER TABLE "User" ADD CONSTRAINT "User_role_scope" CHECK ("role" IN ('ADMIN', 'AUDITOR'));
