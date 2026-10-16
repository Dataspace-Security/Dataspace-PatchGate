-- Tactical seal: out-of-band Tactical activity (audit-log entries not made by PatchGate's service account,
-- update approvals PatchGate never set) + the per-connector audit cursor. Idempotent where practical.
--
-- Row-Level Security: TacticalActivity is tenant-owned (tenantId = bank) with the standard tenant_isolation
-- policy (ENABLE + FORCE), like ConnectorOutage.

-- New job type (read-only: the connector reads Tactical's audit log)
ALTER TYPE "ConnectorJobType" ADD VALUE IF NOT EXISTS 'TACTICAL_AUDIT_SYNC';

ALTER TABLE "Connector" ADD COLUMN IF NOT EXISTS "tacticalAuditCursor" INTEGER NOT NULL DEFAULT 0;
ALTER TABLE "Connector" ADD COLUMN IF NOT EXISTS "tacticalHumanSeenAt" TIMESTAMP(3);

CREATE TABLE IF NOT EXISTS "TacticalActivity" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "connectorId" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "dedupeKey" TEXT NOT NULL,
    "tacticalId" INTEGER,
    "occurredAt" TIMESTAMP(3) NOT NULL,
    "actor" TEXT NOT NULL,
    "action" TEXT NOT NULL,
    "objectType" TEXT NOT NULL,
    "agentHostname" TEXT,
    "agentId" TEXT,
    "message" TEXT,
    "ip" TEXT,
    "receivedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "acknowledgedAt" TIMESTAMP(3),
    "acknowledgedBy" TEXT,
    CONSTRAINT "TacticalActivity_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX IF NOT EXISTS "TacticalActivity_connectorId_dedupeKey_key" ON "TacticalActivity"("connectorId", "dedupeKey");
CREATE INDEX IF NOT EXISTS "TacticalActivity_tenantId_receivedAt_idx" ON "TacticalActivity"("tenantId", "receivedAt");
CREATE INDEX IF NOT EXISTS "TacticalActivity_tenantId_acknowledgedAt_idx" ON "TacticalActivity"("tenantId", "acknowledgedAt");

ALTER TABLE "TacticalActivity" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "TacticalActivity" FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON "TacticalActivity";
CREATE POLICY tenant_isolation ON "TacticalActivity"
  USING ("tenantId" = current_setting('app.tenant_id', true) OR current_setting('app.scope', true) = 'platform')
  WITH CHECK ("tenantId" = current_setting('app.tenant_id', true) OR current_setting('app.scope', true) = 'platform');

-- Usable inside withTenant()/withPlatform() (SET LOCAL ROLE patchgate_tenant).
GRANT SELECT, INSERT, UPDATE, DELETE ON "TacticalActivity" TO patchgate_tenant;
