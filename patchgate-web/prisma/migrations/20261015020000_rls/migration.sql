-- Row-Level Security: second isolation layer between banks (ARCHITECTURE-HOSTED §4).
--
-- The app enters a bank's data only through withTenant()/withPlatform() (src/lib/tenancy/db.ts), which,
-- inside one transaction, run:
--   set_config('app.scope', 'tenant' | 'platform', true)
--   set_config('app.tenant_id', <bank id>, true)        -- tenant scope only
--   set_config('role', 'patchgate_tenant', true)        -- = SET LOCAL ROLE
-- Switching to the non-superuser, NOBYPASSRLS role makes the policies apply even when the login role is a
-- superuser (dev Docker) or the table owner. A query that forgets its tenant filter therefore cannot
-- read or write another bank's rows.
--
-- Requires the migrating role to be allowed to create roles (superuser or CREATEROLE). Roles are
-- cluster-wide, so the role is created once and re-used by every database in the cluster.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'patchgate_tenant') THEN
    CREATE ROLE patchgate_tenant NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOINHERIT;
  END IF;
END
$$;

-- The application login must be able to SET ROLE to it.
GRANT patchgate_tenant TO CURRENT_USER;

GRANT USAGE ON SCHEMA public TO patchgate_tenant;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO patchgate_tenant;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO patchgate_tenant;
REVOKE ALL ON "_prisma_migrations" FROM patchgate_tenant;
-- Tables added by later migrations are usable inside withTenant()/withPlatform() too.
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO patchgate_tenant;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO patchgate_tenant;

-- ---------------------------------------------------------------------------------------------
-- Fully converted tenant tables: ENABLE + FORCE (the table owner is subject to the policy too).
-- ---------------------------------------------------------------------------------------------

ALTER TABLE "Ring" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "Ring" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "Ring"
  USING ("tenantId" = current_setting('app.tenant_id', true) OR current_setting('app.scope', true) = 'platform')
  WITH CHECK ("tenantId" = current_setting('app.tenant_id', true) OR current_setting('app.scope', true) = 'platform');

ALTER TABLE "MaintenanceWindow" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "MaintenanceWindow" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "MaintenanceWindow"
  USING ("tenantId" = current_setting('app.tenant_id', true) OR current_setting('app.scope', true) = 'platform')
  WITH CHECK ("tenantId" = current_setting('app.tenant_id', true) OR current_setting('app.scope', true) = 'platform');

ALTER TABLE "Endpoint" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "Endpoint" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "Endpoint"
  USING ("tenantId" = current_setting('app.tenant_id', true) OR current_setting('app.scope', true) = 'platform')
  WITH CHECK ("tenantId" = current_setting('app.tenant_id', true) OR current_setting('app.scope', true) = 'platform');

ALTER TABLE "EndpointPatchState" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "EndpointPatchState" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "EndpointPatchState"
  USING ("tenantId" = current_setting('app.tenant_id', true) OR current_setting('app.scope', true) = 'platform')
  WITH CHECK ("tenantId" = current_setting('app.tenant_id', true) OR current_setting('app.scope', true) = 'platform');

ALTER TABLE "ChangeRequest" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "ChangeRequest" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "ChangeRequest"
  USING ("tenantId" = current_setting('app.tenant_id', true) OR current_setting('app.scope', true) = 'platform')
  WITH CHECK ("tenantId" = current_setting('app.tenant_id', true) OR current_setting('app.scope', true) = 'platform');

-- No tenantId column: visible exactly when its change request is (the sub-select is itself under RLS).
ALTER TABLE "ChangeRequestPatch" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "ChangeRequestPatch" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "ChangeRequestPatch"
  USING (EXISTS (SELECT 1 FROM "ChangeRequest" c WHERE c."id" = "ChangeRequestPatch"."changeRequestId"))
  WITH CHECK (EXISTS (SELECT 1 FROM "ChangeRequest" c WHERE c."id" = "ChangeRequestPatch"."changeRequestId"));

ALTER TABLE "Deployment" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "Deployment" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "Deployment"
  USING ("tenantId" = current_setting('app.tenant_id', true) OR current_setting('app.scope', true) = 'platform')
  WITH CHECK ("tenantId" = current_setting('app.tenant_id', true) OR current_setting('app.scope', true) = 'platform');

ALTER TABLE "InstalledSoftware" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "InstalledSoftware" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "InstalledSoftware"
  USING ("tenantId" = current_setting('app.tenant_id', true) OR current_setting('app.scope', true) = 'platform')
  WITH CHECK ("tenantId" = current_setting('app.tenant_id', true) OR current_setting('app.scope', true) = 'platform');

ALTER TABLE "DiscoveredApp" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "DiscoveredApp" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "DiscoveredApp"
  USING ("tenantId" = current_setting('app.tenant_id', true) OR current_setting('app.scope', true) = 'platform')
  WITH CHECK ("tenantId" = current_setting('app.tenant_id', true) OR current_setting('app.scope', true) = 'platform');

ALTER TABLE "TenantApp" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "TenantApp" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "TenantApp"
  USING ("tenantId" = current_setting('app.tenant_id', true) OR current_setting('app.scope', true) = 'platform')
  WITH CHECK ("tenantId" = current_setting('app.tenant_id', true) OR current_setting('app.scope', true) = 'platform');

-- ---------------------------------------------------------------------------------------------
-- ENABLE only (no FORCE): policies bind inside withTenant()/withPlatform(); the owner login still
-- bypasses them, so code that has not adopted the helpers yet keeps working.
--  * Connector / ConnectorEnrollment / ConnectorJob: connector + admin code paths (FORCE once adopted).
--  * AuditEvent / AuditAnchor: one hash chain per bank, NULL = platform chain (platform scope only).
--    Writes are additionally guarded by the append-only triggers + HMAC chain.
-- ---------------------------------------------------------------------------------------------

ALTER TABLE "Connector" ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "Connector"
  USING ("tenantId" = current_setting('app.tenant_id', true) OR current_setting('app.scope', true) = 'platform')
  WITH CHECK ("tenantId" = current_setting('app.tenant_id', true) OR current_setting('app.scope', true) = 'platform');

ALTER TABLE "ConnectorEnrollment" ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "ConnectorEnrollment"
  USING ("tenantId" = current_setting('app.tenant_id', true) OR current_setting('app.scope', true) = 'platform')
  WITH CHECK ("tenantId" = current_setting('app.tenant_id', true) OR current_setting('app.scope', true) = 'platform');

ALTER TABLE "ConnectorJob" ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "ConnectorJob"
  USING ("tenantId" = current_setting('app.tenant_id', true) OR current_setting('app.scope', true) = 'platform')
  WITH CHECK ("tenantId" = current_setting('app.tenant_id', true) OR current_setting('app.scope', true) = 'platform');

ALTER TABLE "AuditEvent" ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "AuditEvent"
  USING ("tenantId" = current_setting('app.tenant_id', true) OR current_setting('app.scope', true) = 'platform')
  WITH CHECK ("tenantId" = current_setting('app.tenant_id', true) OR current_setting('app.scope', true) = 'platform');

ALTER TABLE "AuditAnchor" ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "AuditAnchor"
  USING ("tenantId" = current_setting('app.tenant_id', true) OR current_setting('app.scope', true) = 'platform')
  WITH CHECK ("tenantId" = current_setting('app.tenant_id', true) OR current_setting('app.scope', true) = 'platform');
