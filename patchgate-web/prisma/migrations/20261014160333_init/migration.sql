-- CreateEnum
CREATE TYPE "UserRole" AS ENUM ('VIEWER', 'OPERATOR', 'APPROVER', 'ADMIN');

-- CreateEnum
CREATE TYPE "PatchKind" AS ENUM ('WINDOWS', 'THIRD_PARTY');

-- CreateEnum
CREATE TYPE "PatchSeverity" AS ENUM ('CRITICAL', 'IMPORTANT', 'MODERATE', 'LOW', 'UNSPECIFIED');

-- CreateEnum
CREATE TYPE "EndpointPatchStatus" AS ENUM ('NEEDED', 'INSTALLED', 'FAILED', 'NOT_APPLICABLE');

-- CreateEnum
CREATE TYPE "ChangeRequestStatus" AS ENUM ('DRAFT', 'PENDING_APPROVAL', 'APPROVED', 'REJECTED', 'DEPLOYING', 'COMPLETED', 'PARTIAL', 'FAILED', 'CANCELLED');

-- CreateEnum
CREATE TYPE "DeploymentStatus" AS ENUM ('QUEUED', 'SENDING', 'SENT', 'SUCCEEDED', 'FAILED', 'TIMED_OUT');

-- CreateEnum
CREATE TYPE "RebootPolicy" AS ENUM ('NEVER', 'REQUIRED', 'ALWAYS');

-- CreateEnum
CREATE TYPE "PackageVerification" AS ENUM ('PENDING', 'VERIFIED', 'REJECTED');

-- CreateTable
CREATE TABLE "User" (
    "id" TEXT NOT NULL,
    "upn" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "role" "UserRole" NOT NULL DEFAULT 'VIEWER',
    "active" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "User_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Ring" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "wsusGroup" TEXT NOT NULL,
    "order" INTEGER NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Ring_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "MaintenanceWindow" (
    "id" TEXT NOT NULL,
    "ringId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "cron" TEXT NOT NULL,
    "durationMin" INTEGER NOT NULL,
    "timezone" TEXT NOT NULL DEFAULT 'Asia/Kolkata',
    "rebootPolicy" "RebootPolicy" NOT NULL DEFAULT 'REQUIRED',

    CONSTRAINT "MaintenanceWindow_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Endpoint" (
    "id" TEXT NOT NULL,
    "tacticalAgentId" TEXT NOT NULL,
    "hostname" TEXT NOT NULL,
    "client" TEXT,
    "site" TEXT,
    "osName" TEXT,
    "ringId" TEXT,
    "lastScanAt" TIMESTAMP(3),
    "lastSeenAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Endpoint_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Patch" (
    "id" TEXT NOT NULL,
    "kind" "PatchKind" NOT NULL,
    "externalId" TEXT NOT NULL,
    "kb" TEXT,
    "title" TEXT NOT NULL,
    "classification" TEXT,
    "severity" "PatchSeverity" NOT NULL DEFAULT 'UNSPECIFIED',
    "cves" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "releasedAt" TIMESTAMP(3),
    "supersededById" TEXT,
    "appVersionId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Patch_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EndpointPatchState" (
    "endpointId" TEXT NOT NULL,
    "patchId" TEXT NOT NULL,
    "status" "EndpointPatchStatus" NOT NULL,
    "tacticalUpdatePk" INTEGER,
    "lastResult" TEXT,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "EndpointPatchState_pkey" PRIMARY KEY ("endpointId","patchId")
);

-- CreateTable
CREATE TABLE "ChangeRequest" (
    "id" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "ticketRef" TEXT,
    "ringId" TEXT NOT NULL,
    "windowId" TEXT,
    "status" "ChangeRequestStatus" NOT NULL DEFAULT 'DRAFT',
    "createdById" TEXT NOT NULL,
    "approvedById" TEXT,
    "rejectReason" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "submittedAt" TIMESTAMP(3),
    "decidedAt" TIMESTAMP(3),
    "completedAt" TIMESTAMP(3),

    CONSTRAINT "ChangeRequest_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ChangeRequestPatch" (
    "changeRequestId" TEXT NOT NULL,
    "patchId" TEXT NOT NULL,

    CONSTRAINT "ChangeRequestPatch_pkey" PRIMARY KEY ("changeRequestId","patchId")
);

-- CreateTable
CREATE TABLE "Deployment" (
    "id" TEXT NOT NULL,
    "changeRequestId" TEXT NOT NULL,
    "endpointId" TEXT NOT NULL,
    "status" "DeploymentStatus" NOT NULL DEFAULT 'QUEUED',
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "nextAttemptAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "error" TEXT,
    "startedAt" TIMESTAMP(3),
    "finishedAt" TIMESTAMP(3),

    CONSTRAINT "Deployment_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "App" (
    "id" TEXT NOT NULL,
    "wingetId" TEXT NOT NULL,
    "displayName" TEXT NOT NULL,
    "inventoryMatch" TEXT NOT NULL,
    "expectedPublisher" TEXT NOT NULL,
    "allowedDomains" TEXT[],
    "autoUpdateDisabled" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "App_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AppVersion" (
    "id" TEXT NOT NULL,
    "appId" TEXT NOT NULL,
    "version" TEXT NOT NULL,
    "installerUrl" TEXT NOT NULL,
    "sha256" TEXT NOT NULL,
    "silentArgs" TEXT NOT NULL,
    "verification" "PackageVerification" NOT NULL DEFAULT 'PENDING',
    "rejectReason" TEXT,
    "repoPath" TEXT,
    "availableAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AppVersion_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AuditEvent" (
    "seq" BIGSERIAL NOT NULL,
    "ts" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "actor" TEXT NOT NULL,
    "action" TEXT NOT NULL,
    "entity" TEXT NOT NULL,
    "entityId" TEXT NOT NULL,
    "payload" JSONB NOT NULL,
    "prevHash" TEXT NOT NULL,
    "hash" TEXT NOT NULL,

    CONSTRAINT "AuditEvent_pkey" PRIMARY KEY ("seq")
);

-- CreateIndex
CREATE UNIQUE INDEX "User_upn_key" ON "User"("upn");

-- CreateIndex
CREATE UNIQUE INDEX "Ring_name_key" ON "Ring"("name");

-- CreateIndex
CREATE UNIQUE INDEX "Ring_wsusGroup_key" ON "Ring"("wsusGroup");

-- CreateIndex
CREATE UNIQUE INDEX "Ring_order_key" ON "Ring"("order");

-- CreateIndex
CREATE UNIQUE INDEX "Endpoint_tacticalAgentId_key" ON "Endpoint"("tacticalAgentId");

-- CreateIndex
CREATE INDEX "Endpoint_ringId_idx" ON "Endpoint"("ringId");

-- CreateIndex
CREATE INDEX "Endpoint_site_idx" ON "Endpoint"("site");

-- CreateIndex
CREATE UNIQUE INDEX "Patch_externalId_key" ON "Patch"("externalId");

-- CreateIndex
CREATE UNIQUE INDEX "Patch_appVersionId_key" ON "Patch"("appVersionId");

-- CreateIndex
CREATE INDEX "Patch_kind_severity_idx" ON "Patch"("kind", "severity");

-- CreateIndex
CREATE INDEX "Patch_kb_idx" ON "Patch"("kb");

-- CreateIndex
CREATE INDEX "EndpointPatchState_patchId_status_idx" ON "EndpointPatchState"("patchId", "status");

-- CreateIndex
CREATE INDEX "ChangeRequest_status_idx" ON "ChangeRequest"("status");

-- CreateIndex
CREATE INDEX "Deployment_status_nextAttemptAt_idx" ON "Deployment"("status", "nextAttemptAt");

-- CreateIndex
CREATE UNIQUE INDEX "Deployment_changeRequestId_endpointId_key" ON "Deployment"("changeRequestId", "endpointId");

-- CreateIndex
CREATE UNIQUE INDEX "App_wingetId_key" ON "App"("wingetId");

-- CreateIndex
CREATE UNIQUE INDEX "AppVersion_appId_version_key" ON "AppVersion"("appId", "version");

-- CreateIndex
CREATE UNIQUE INDEX "AuditEvent_hash_key" ON "AuditEvent"("hash");

-- CreateIndex
CREATE INDEX "AuditEvent_entity_entityId_idx" ON "AuditEvent"("entity", "entityId");

-- AddForeignKey
ALTER TABLE "MaintenanceWindow" ADD CONSTRAINT "MaintenanceWindow_ringId_fkey" FOREIGN KEY ("ringId") REFERENCES "Ring"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Endpoint" ADD CONSTRAINT "Endpoint_ringId_fkey" FOREIGN KEY ("ringId") REFERENCES "Ring"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Patch" ADD CONSTRAINT "Patch_supersededById_fkey" FOREIGN KEY ("supersededById") REFERENCES "Patch"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Patch" ADD CONSTRAINT "Patch_appVersionId_fkey" FOREIGN KEY ("appVersionId") REFERENCES "AppVersion"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "EndpointPatchState" ADD CONSTRAINT "EndpointPatchState_endpointId_fkey" FOREIGN KEY ("endpointId") REFERENCES "Endpoint"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "EndpointPatchState" ADD CONSTRAINT "EndpointPatchState_patchId_fkey" FOREIGN KEY ("patchId") REFERENCES "Patch"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ChangeRequest" ADD CONSTRAINT "ChangeRequest_ringId_fkey" FOREIGN KEY ("ringId") REFERENCES "Ring"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ChangeRequest" ADD CONSTRAINT "ChangeRequest_windowId_fkey" FOREIGN KEY ("windowId") REFERENCES "MaintenanceWindow"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ChangeRequest" ADD CONSTRAINT "ChangeRequest_createdById_fkey" FOREIGN KEY ("createdById") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ChangeRequest" ADD CONSTRAINT "ChangeRequest_approvedById_fkey" FOREIGN KEY ("approvedById") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ChangeRequestPatch" ADD CONSTRAINT "ChangeRequestPatch_changeRequestId_fkey" FOREIGN KEY ("changeRequestId") REFERENCES "ChangeRequest"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ChangeRequestPatch" ADD CONSTRAINT "ChangeRequestPatch_patchId_fkey" FOREIGN KEY ("patchId") REFERENCES "Patch"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Deployment" ADD CONSTRAINT "Deployment_changeRequestId_fkey" FOREIGN KEY ("changeRequestId") REFERENCES "ChangeRequest"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Deployment" ADD CONSTRAINT "Deployment_endpointId_fkey" FOREIGN KEY ("endpointId") REFERENCES "Endpoint"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AppVersion" ADD CONSTRAINT "AppVersion_appId_fkey" FOREIGN KEY ("appId") REFERENCES "App"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- ---------------------------------------------------------------------------
-- PatchGate hand-written constraints (not expressible in Prisma schema)
-- ---------------------------------------------------------------------------

-- At most ONE in-flight deployment per endpoint across all change requests.
-- Tactical's install endpoint installs every approved update on an agent, so two
-- concurrent change requests on the same PC would install each other's patches.
CREATE UNIQUE INDEX "Deployment_one_active_per_endpoint"
  ON "Deployment" ("endpointId")
  WHERE "status" IN ('SENDING', 'SENT');

-- Audit log is append-only: block UPDATE / DELETE / TRUNCATE at the database level.
CREATE FUNCTION patchgate_audit_immutable() RETURNS trigger
  LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'AuditEvent is append-only (% blocked)', TG_OP;
END;
$$;

CREATE TRIGGER "AuditEvent_no_update_delete"
  BEFORE UPDATE OR DELETE ON "AuditEvent"
  FOR EACH ROW EXECUTE FUNCTION patchgate_audit_immutable();

CREATE TRIGGER "AuditEvent_no_truncate"
  BEFORE TRUNCATE ON "AuditEvent"
  FOR EACH STATEMENT EXECUTE FUNCTION patchgate_audit_immutable();
