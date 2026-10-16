-- Role model (2026-10-16): two roles everywhere, ADMIN and AUDITOR (read-only).
-- Own migration: a new enum value can only be used after the transaction that added it has committed;
-- the data mapping and the CHECK constraint follow in 20261016140100_role_scope.
ALTER TYPE "UserRole" ADD VALUE IF NOT EXISTS 'AUDITOR';
