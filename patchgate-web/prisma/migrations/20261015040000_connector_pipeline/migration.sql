-- Connector job pipeline (protocol v1 server side).
--
-- 1. Connector.heartbeat: last heartbeat body (cache size, Tactical reachability, agent count, SIEM relay)
--    shown on /connectors and the dashboard health card. ConnectorJob.processedAt/processAttempts:
--    results are stored on receipt and applied asynchronously (retried on the next worker tick).
-- 2. Every connector code path now goes through withTenant()/withPlatform() (src/lib/connector/**), so
--    Row-Level Security is FORCED on the connector tables too: the table owner is subject to the policy,
--    exactly like the other tenant tables (20261015020000_rls).
--    Idempotent (IF NOT EXISTS): databases where these columns were already added converge too.
-- 3. Lookup indexes for the job queue: per-connector cache state (CACHE_PACKAGE by package SHA-256) and
--    in-flight install jobs per connector (LAN protection cap).

ALTER TABLE "Connector" ADD COLUMN IF NOT EXISTS "heartbeat" JSONB;

-- Results are accepted quickly and applied asynchronously (big COLLECT pages must not hold the request).
ALTER TABLE "ConnectorJob" ADD COLUMN IF NOT EXISTS "processedAt" TIMESTAMP(3),
ADD COLUMN IF NOT EXISTS "processAttempts" INTEGER NOT NULL DEFAULT 0;

ALTER TABLE "Connector" FORCE ROW LEVEL SECURITY;
ALTER TABLE "ConnectorEnrollment" FORCE ROW LEVEL SECURITY;
ALTER TABLE "ConnectorJob" FORCE ROW LEVEL SECURITY;

-- Which packages a connector has cached / is caching (entitlement + "cache before deploy").
CREATE INDEX IF NOT EXISTS "ConnectorJob_cache_sha256_idx"
  ON "ConnectorJob" ("connectorId", ((("payload" -> 'package') ->> 'sha256')))
  WHERE "type" = 'CACHE_PACKAGE';

-- Accepted results still waiting for their handler.
CREATE INDEX IF NOT EXISTS "ConnectorJob_unprocessed_idx"
  ON "ConnectorJob" ("completedAt")
  WHERE "processedAt" IS NULL AND "completedAt" IS NOT NULL;

-- In-flight install jobs per connector (maxConcurrentInstalls).
CREATE INDEX IF NOT EXISTS "ConnectorJob_inflight_installs_idx"
  ON "ConnectorJob" ("connectorId")
  WHERE "type" IN ('DEPLOY_WINDOWS', 'DEPLOY_PACKAGE', 'WU_INSTALL') AND "status" IN ('QUEUED', 'DELIVERED');
