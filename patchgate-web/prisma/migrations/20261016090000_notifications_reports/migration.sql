-- Notifications (transactional outbox, settings, opt-outs, alert state), connector outage history and a
-- compliance-report index. Idempotent where practical (IF NOT EXISTS), like the earlier migrations.
--
-- Row-Level Security: Notification / NotificationSetting / NotificationAlert / ConnectorOutage are tenant-owned
-- (tenantId = bank, NULL = platform) — ENABLE + FORCE with the standard tenant_isolation policy, so a bank scope
-- never sees another bank's (or the platform's) rows. One extra read-only policy lets a bank-scoped transaction
-- read the PLATFORM notification settings row: an event of bank A that also concerns our staff (e.g. a change
-- request needing a platform approver) resolves the platform webhooks inside bank A's transaction.
-- NotificationOptOut is keyed by user (like "User", no tenant rows): no RLS.

-- Enums ----------------------------------------------------------------------------------------------
DO $$ BEGIN
  CREATE TYPE "NotificationChannel" AS ENUM ('EMAIL', 'WEBHOOK');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN
  CREATE TYPE "NotificationStatus" AS ENUM ('PENDING', 'SENDING', 'SENT', 'DEAD', 'SKIPPED');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- Notification (outbox) --------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS "Notification" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT,
    "event" TEXT NOT NULL,
    "severity" TEXT NOT NULL,
    "channel" "NotificationChannel" NOT NULL,
    "target" TEXT NOT NULL,
    "recipientUserId" TEXT,
    "subject" TEXT NOT NULL,
    "bodyText" TEXT NOT NULL,
    "bodyHtml" TEXT NOT NULL,
    "link" TEXT,
    "status" "NotificationStatus" NOT NULL DEFAULT 'PENDING',
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "nextAttemptAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "claimedAt" TIMESTAMP(3),
    "lastError" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "sentAt" TIMESTAMP(3),
    CONSTRAINT "Notification_pkey" PRIMARY KEY ("id")
);
CREATE INDEX IF NOT EXISTS "Notification_status_nextAttemptAt_idx" ON "Notification"("status", "nextAttemptAt");
CREATE INDEX IF NOT EXISTS "Notification_tenantId_createdAt_idx" ON "Notification"("tenantId", "createdAt");
CREATE INDEX IF NOT EXISTS "Notification_createdAt_idx" ON "Notification"("createdAt");

-- NotificationSetting --------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS "NotificationSetting" (
    "scope" TEXT NOT NULL,
    "tenantId" TEXT,
    "webhookUrls" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "disabledEvents" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "updatedBy" TEXT,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "NotificationSetting_pkey" PRIMARY KEY ("scope")
);
-- scope is the bank id (tenantId) or 'platform' (tenantId NULL) — never anything else.
DO $$ BEGIN
  ALTER TABLE "NotificationSetting" ADD CONSTRAINT "NotificationSetting_scope_check"
    CHECK (("scope" = 'platform' AND "tenantId" IS NULL) OR ("tenantId" IS NOT NULL AND "scope" = "tenantId"));
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- NotificationOptOut -------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS "NotificationOptOut" (
    "userId" TEXT NOT NULL,
    "event" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "NotificationOptOut_pkey" PRIMARY KEY ("userId", "event")
);

-- NotificationAlert ------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS "NotificationAlert" (
    "key" TEXT NOT NULL,
    "tenantId" TEXT,
    "raisedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "NotificationAlert_pkey" PRIMARY KEY ("key")
);

-- ConnectorOutage ------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS "ConnectorOutage" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "connectorId" TEXT NOT NULL,
    "startedAt" TIMESTAMP(3) NOT NULL,
    "detectedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "endedAt" TIMESTAMP(3),
    CONSTRAINT "ConnectorOutage_pkey" PRIMARY KEY ("id")
);
CREATE INDEX IF NOT EXISTS "ConnectorOutage_tenantId_startedAt_idx" ON "ConnectorOutage"("tenantId", "startedAt");
CREATE INDEX IF NOT EXISTS "ConnectorOutage_connectorId_endedAt_idx" ON "ConnectorOutage"("connectorId", "endedAt");
-- At most one open outage per connector (the watcher may run on two instances at once).
CREATE UNIQUE INDEX IF NOT EXISTS "ConnectorOutage_one_open_per_connector" ON "ConnectorOutage"("connectorId") WHERE "endedAt" IS NULL;

-- Compliance reports: missing patches of ONE bank (EndpointPatchState is the biggest table) ---------------------
CREATE INDEX IF NOT EXISTS "EndpointPatchState_tenantId_status_patchId_idx" ON "EndpointPatchState"("tenantId", "status", "patchId");

-- Row-Level Security -------------------------------------------------------------------------------------------
ALTER TABLE "Notification" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "Notification" FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON "Notification";
CREATE POLICY tenant_isolation ON "Notification"
  USING ("tenantId" = current_setting('app.tenant_id', true) OR current_setting('app.scope', true) = 'platform')
  WITH CHECK ("tenantId" = current_setting('app.tenant_id', true) OR current_setting('app.scope', true) = 'platform');

ALTER TABLE "NotificationSetting" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "NotificationSetting" FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON "NotificationSetting";
CREATE POLICY tenant_isolation ON "NotificationSetting"
  USING ("tenantId" = current_setting('app.tenant_id', true) OR current_setting('app.scope', true) = 'platform')
  WITH CHECK ("tenantId" = current_setting('app.tenant_id', true) OR current_setting('app.scope', true) = 'platform');
-- Read-only: a bank-scoped transaction may read the platform row (permissive policies are OR-ed; writes still
-- need the platform scope through tenant_isolation's WITH CHECK).
DROP POLICY IF EXISTS platform_settings_read ON "NotificationSetting";
CREATE POLICY platform_settings_read ON "NotificationSetting" FOR SELECT
  USING ("tenantId" IS NULL AND current_setting('app.scope', true) = 'tenant');

ALTER TABLE "NotificationAlert" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "NotificationAlert" FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON "NotificationAlert";
CREATE POLICY tenant_isolation ON "NotificationAlert"
  USING ("tenantId" = current_setting('app.tenant_id', true) OR current_setting('app.scope', true) = 'platform')
  WITH CHECK ("tenantId" = current_setting('app.tenant_id', true) OR current_setting('app.scope', true) = 'platform');

ALTER TABLE "ConnectorOutage" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "ConnectorOutage" FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON "ConnectorOutage";
CREATE POLICY tenant_isolation ON "ConnectorOutage"
  USING ("tenantId" = current_setting('app.tenant_id', true) OR current_setting('app.scope', true) = 'platform')
  WITH CHECK ("tenantId" = current_setting('app.tenant_id', true) OR current_setting('app.scope', true) = 'platform');

-- Usable inside withTenant()/withPlatform() (SET LOCAL ROLE patchgate_tenant).
GRANT SELECT, INSERT, UPDATE, DELETE ON "Notification", "NotificationSetting", "NotificationOptOut", "NotificationAlert", "ConnectorOutage" TO patchgate_tenant;
