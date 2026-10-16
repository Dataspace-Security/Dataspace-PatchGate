-- Deployment pipeline hardening (review round 2).
--
-- 1. ChangeRequestTarget + ChangeRequest.targetCount: the target endpoints are snapshotted when a change
--    request is submitted; the approver approves exactly that set and deployments only ever go to it.
--    Requests already submitted/approved get their snapshot from the ring as it is now.
-- 2. ChangeRequest.deployDeadlineAt: deployments not started by then are TIMED_OUT so the request finalises.
-- 3. Deployment.connectorId (denormalised Endpoint.connectorId, synced for QUEUED deployments by a trigger)
--    + index (connectorId, status, nextAttemptAt): the per-connector pump reads one index.
-- 4. Deployment.failureKind: only INSTALL failures (and confirmation timeouts) count towards ring stop.
-- 5. ConnectorJob.retryOfJobId UNIQUE: idempotency key for retries (a result applied twice after a crash
--    never schedules a second retry). Partial index for the retention purge of finished jobs.
-- 6. AuditVerifyCheckpoint: incremental audit-chain verification state (platform data, no tenant rows).
-- Idempotent where practical (IF NOT EXISTS), like the earlier pipeline migrations.

DO $$ BEGIN
  CREATE TYPE "DeploymentFailureKind" AS ENUM ('INSTALL', 'PLANNING', 'CACHE', 'RING_STOPPED', 'DEADLINE', 'UNMANAGED', 'INTERNAL');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- ---- ChangeRequest ----
ALTER TABLE "ChangeRequest" ADD COLUMN IF NOT EXISTS "targetCount" INTEGER,
ADD COLUMN IF NOT EXISTS "deployDeadlineAt" TIMESTAMP(3);

CREATE TABLE IF NOT EXISTS "ChangeRequestTarget" (
    "changeRequestId" TEXT NOT NULL,
    "endpointId" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    CONSTRAINT "ChangeRequestTarget_pkey" PRIMARY KEY ("changeRequestId", "endpointId")
);
CREATE INDEX IF NOT EXISTS "ChangeRequestTarget_tenantId_idx" ON "ChangeRequestTarget"("tenantId");
DO $$ BEGIN
  ALTER TABLE "ChangeRequestTarget" ADD CONSTRAINT "ChangeRequestTarget_changeRequestId_fkey"
    FOREIGN KEY ("changeRequestId") REFERENCES "ChangeRequest"("id") ON DELETE CASCADE ON UPDATE CASCADE;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

ALTER TABLE "ChangeRequestTarget" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "ChangeRequestTarget" FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON "ChangeRequestTarget";
CREATE POLICY tenant_isolation ON "ChangeRequestTarget"
  USING ("tenantId" = current_setting('app.tenant_id', true) OR current_setting('app.scope', true) = 'platform')
  WITH CHECK ("tenantId" = current_setting('app.tenant_id', true) OR current_setting('app.scope', true) = 'platform');
GRANT SELECT, INSERT, UPDATE, DELETE ON "ChangeRequestTarget" TO patchgate_tenant;

-- Snapshot for requests that were submitted before this migration (pending / approved / deploying).
INSERT INTO "ChangeRequestTarget" ("changeRequestId", "endpointId", "tenantId")
SELECT c."id", e."id", c."tenantId"
  FROM "ChangeRequest" c
  JOIN "Endpoint" e ON e."ringId" = c."ringId" AND e."tenantId" = c."tenantId"
 WHERE c."status" IN ('PENDING_APPROVAL', 'APPROVED')
ON CONFLICT DO NOTHING;
INSERT INTO "ChangeRequestTarget" ("changeRequestId", "endpointId", "tenantId")
SELECT d."changeRequestId", d."endpointId", d."tenantId" FROM "Deployment" d
ON CONFLICT DO NOTHING;
UPDATE "ChangeRequest" c
   SET "targetCount" = (SELECT COUNT(*) FROM "ChangeRequestTarget" t WHERE t."changeRequestId" = c."id")
 WHERE c."status" NOT IN ('DRAFT') AND c."targetCount" IS NULL;
UPDATE "ChangeRequest" SET "deployDeadlineAt" = now() + interval '14 days'
 WHERE "status" = 'DEPLOYING' AND "deployDeadlineAt" IS NULL;

-- ---- Deployment ----
ALTER TABLE "Deployment" ADD COLUMN IF NOT EXISTS "failureKind" "DeploymentFailureKind",
ADD COLUMN IF NOT EXISTS "connectorId" TEXT;
UPDATE "Deployment" d SET "connectorId" = e."connectorId"
  FROM "Endpoint" e WHERE e."id" = d."endpointId" AND d."connectorId" IS DISTINCT FROM e."connectorId";
CREATE INDEX IF NOT EXISTS "Deployment_connectorId_status_nextAttemptAt_idx" ON "Deployment"("connectorId", "status", "nextAttemptAt");
-- Historic failures were install failures unless a note says otherwise (ring stop / unmanaged).
UPDATE "Deployment" SET "failureKind" = CASE
    WHEN "note" LIKE 'ring stopped:%' THEN 'RING_STOPPED'::"DeploymentFailureKind"
    WHEN "error" LIKE 'no active site connector%' THEN 'UNMANAGED'::"DeploymentFailureKind"
    ELSE 'INSTALL'::"DeploymentFailureKind" END
 WHERE "status" IN ('FAILED', 'TIMED_OUT') AND "failureKind" IS NULL;

-- A PC that moves to another connector (or loses its connector) takes its not-yet-started deployments
-- along. Started ones (SENDING / SENT) stay with the connector that runs their jobs.
CREATE OR REPLACE FUNCTION patchgate_sync_deployment_connector() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW."connectorId" IS DISTINCT FROM OLD."connectorId" THEN
    UPDATE "Deployment" SET "connectorId" = NEW."connectorId"
     WHERE "endpointId" = NEW."id" AND "tenantId" = NEW."tenantId" AND "status" = 'QUEUED';
  END IF;
  RETURN NEW;
END
$$;
DROP TRIGGER IF EXISTS "Endpoint_sync_deployment_connector" ON "Endpoint";
CREATE TRIGGER "Endpoint_sync_deployment_connector"
  AFTER UPDATE OF "connectorId" ON "Endpoint"
  FOR EACH ROW EXECUTE FUNCTION patchgate_sync_deployment_connector();

-- ---- ConnectorJob ----
ALTER TABLE "ConnectorJob" ADD COLUMN IF NOT EXISTS "retryOfJobId" TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS "ConnectorJob_retryOfJobId_key" ON "ConnectorJob"("retryOfJobId");
-- Retention purge of finished, applied jobs.
CREATE INDEX IF NOT EXISTS "ConnectorJob_finished_idx" ON "ConnectorJob" ("completedAt") WHERE "processedAt" IS NOT NULL;

-- ---- Audit verification checkpoints ----
CREATE TABLE IF NOT EXISTS "AuditVerifyCheckpoint" (
    "chain" TEXT NOT NULL,
    "tenantId" TEXT,
    "seq" BIGINT NOT NULL,
    "hash" TEXT NOT NULL,
    "count" BIGINT NOT NULL,
    "anchorSeq" BIGINT NOT NULL,
    "valid" BOOLEAN NOT NULL,
    "problem" TEXT,
    "verifiedAt" TIMESTAMP(3) NOT NULL,
    "fullVerifiedAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "AuditVerifyCheckpoint_pkey" PRIMARY KEY ("chain")
);
GRANT SELECT, INSERT, UPDATE, DELETE ON "AuditVerifyCheckpoint" TO patchgate_tenant;
