-- CreateEnum
CREATE TYPE "ConnectorStatus" AS ENUM ('ACTIVE', 'REVOKED');

-- CreateEnum
CREATE TYPE "ConnectorJobType" AS ENUM ('SYNC_AGENTS', 'SCAN', 'COLLECT', 'DEPLOY_WINDOWS', 'DEPLOY_PACKAGE', 'RESET_APPROVALS', 'CACHE_PACKAGE');

-- CreateEnum
CREATE TYPE "ConnectorJobStatus" AS ENUM ('QUEUED', 'DELIVERED', 'SUCCEEDED', 'FAILED', 'EXPIRED', 'CANCELLED');

-- DropIndex
DROP INDEX "AuditAnchor_seq_idx";

-- DropIndex
DROP INDEX "DiscoveredApp_key_key";

-- DropIndex
DROP INDEX "Ring_name_key";

-- DropIndex
DROP INDEX "Ring_order_key";

-- DropIndex
DROP INDEX "Ring_wsusGroup_key";

-- AlterTable
ALTER TABLE "AuditAnchor" ADD COLUMN     "tenantId" TEXT;

-- AlterTable
ALTER TABLE "AuditEvent" ADD COLUMN     "tenantId" TEXT;

-- AlterTable
ALTER TABLE "ChangeRequest" ADD COLUMN     "tenantId" TEXT NOT NULL DEFAULT 'tenant-default';

-- AlterTable
ALTER TABLE "Deployment" ADD COLUMN     "tenantId" TEXT NOT NULL DEFAULT 'tenant-default';

-- AlterTable
ALTER TABLE "DiscoveredApp" ADD COLUMN     "tenantId" TEXT NOT NULL DEFAULT 'tenant-default';

-- AlterTable
ALTER TABLE "Endpoint" ADD COLUMN     "connectorId" TEXT,
ADD COLUMN     "tenantId" TEXT NOT NULL DEFAULT 'tenant-default';

-- AlterTable
ALTER TABLE "EndpointPatchState" ADD COLUMN     "tenantId" TEXT NOT NULL DEFAULT 'tenant-default';

-- AlterTable
ALTER TABLE "InstalledSoftware" ADD COLUMN     "tenantId" TEXT NOT NULL DEFAULT 'tenant-default';

-- AlterTable
ALTER TABLE "MaintenanceWindow" ADD COLUMN     "tenantId" TEXT NOT NULL DEFAULT 'tenant-default';

-- AlterTable
ALTER TABLE "Ring" ADD COLUMN     "tenantId" TEXT NOT NULL DEFAULT 'tenant-default';

-- AlterTable
ALTER TABLE "User" ADD COLUMN     "failedLogins" INTEGER NOT NULL DEFAULT 0,
ADD COLUMN     "lockedUntil" TIMESTAMP(3),
ADD COLUMN     "mustChangePassword" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "passwordChangedAt" TIMESTAMP(3),
ADD COLUMN     "passwordHash" TEXT,
ADD COLUMN     "tenantId" TEXT,
ADD COLUMN     "totpEnabled" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "totpLastStep" INTEGER,
ADD COLUMN     "totpSecretEnc" TEXT;

-- CreateTable
CREATE TABLE "Tenant" (
    "id" TEXT NOT NULL,
    "slug" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "active" BOOLEAN NOT NULL DEFAULT true,
    "requireBankApproval" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Tenant_pkey" PRIMARY KEY ("id")
);

-- Backfill: everything that existed before multi-tenancy belongs to one default bank.
INSERT INTO "Tenant" ("id", "slug", "name") VALUES ('tenant-default', 'default', 'Default bank');

-- CreateTable
CREATE TABLE "AuthChallenge" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "pendingSecretEnc" TEXT,
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "returnTo" TEXT NOT NULL DEFAULT '/',
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AuthChallenge_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Connector" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "publicKey" TEXT NOT NULL,
    "status" "ConnectorStatus" NOT NULL DEFAULT 'ACTIVE',
    "version" TEXT,
    "enrolledAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeenAt" TIMESTAMP(3),
    "cacheBaseUrl" TEXT,
    "maxConcurrentInstalls" INTEGER NOT NULL DEFAULT 50,
    "bandwidthLimitMbps" INTEGER,
    "standbyOf" TEXT,

    CONSTRAINT "Connector_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ConnectorEnrollment" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "createdBy" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "usedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ConnectorEnrollment_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ConnectorNonce" (
    "connectorId" TEXT NOT NULL,
    "nonce" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ConnectorNonce_pkey" PRIMARY KEY ("connectorId","nonce")
);

-- CreateTable
CREATE TABLE "ConnectorJob" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "connectorId" TEXT NOT NULL,
    "type" "ConnectorJobType" NOT NULL,
    "payload" JSONB NOT NULL,
    "signature" TEXT NOT NULL,
    "status" "ConnectorJobStatus" NOT NULL DEFAULT 'QUEUED',
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "notBefore" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "deliveredAt" TIMESTAMP(3),
    "completedAt" TIMESTAMP(3),
    "result" JSONB,
    "error" TEXT,
    "deploymentId" TEXT,
    "changeRequestId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ConnectorJob_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "TenantApp" (
    "tenantId" TEXT NOT NULL,
    "appId" TEXT NOT NULL,
    "enabledAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "enabledBy" TEXT NOT NULL,

    CONSTRAINT "TenantApp_pkey" PRIMARY KEY ("tenantId","appId")
);

-- CreateIndex
CREATE UNIQUE INDEX "Tenant_slug_key" ON "Tenant"("slug");

-- CreateIndex
CREATE INDEX "AuthChallenge_expiresAt_idx" ON "AuthChallenge"("expiresAt");

-- CreateIndex
CREATE INDEX "Connector_tenantId_idx" ON "Connector"("tenantId");

-- CreateIndex
CREATE UNIQUE INDEX "Connector_tenantId_name_key" ON "Connector"("tenantId", "name");

-- CreateIndex
CREATE INDEX "ConnectorEnrollment_tenantId_idx" ON "ConnectorEnrollment"("tenantId");

-- CreateIndex
CREATE INDEX "ConnectorNonce_expiresAt_idx" ON "ConnectorNonce"("expiresAt");

-- CreateIndex
CREATE INDEX "ConnectorJob_connectorId_status_notBefore_idx" ON "ConnectorJob"("connectorId", "status", "notBefore");

-- CreateIndex
CREATE INDEX "ConnectorJob_tenantId_status_idx" ON "ConnectorJob"("tenantId", "status");

-- CreateIndex
CREATE INDEX "ConnectorJob_deploymentId_idx" ON "ConnectorJob"("deploymentId");

-- CreateIndex
CREATE INDEX "AuditAnchor_tenantId_seq_idx" ON "AuditAnchor"("tenantId", "seq");

-- CreateIndex
CREATE INDEX "AuditEvent_tenantId_seq_idx" ON "AuditEvent"("tenantId", "seq");

-- CreateIndex
CREATE INDEX "ChangeRequest_tenantId_idx" ON "ChangeRequest"("tenantId");

-- CreateIndex
CREATE INDEX "Deployment_tenantId_idx" ON "Deployment"("tenantId");

-- CreateIndex
CREATE UNIQUE INDEX "DiscoveredApp_tenantId_key_key" ON "DiscoveredApp"("tenantId", "key");

-- CreateIndex
CREATE INDEX "Endpoint_connectorId_idx" ON "Endpoint"("connectorId");

-- CreateIndex
CREATE INDEX "Endpoint_tenantId_idx" ON "Endpoint"("tenantId");

-- CreateIndex
CREATE INDEX "EndpointPatchState_tenantId_idx" ON "EndpointPatchState"("tenantId");

-- CreateIndex
CREATE INDEX "InstalledSoftware_tenantId_idx" ON "InstalledSoftware"("tenantId");

-- CreateIndex
CREATE INDEX "MaintenanceWindow_tenantId_idx" ON "MaintenanceWindow"("tenantId");

-- CreateIndex
CREATE UNIQUE INDEX "Ring_tenantId_name_key" ON "Ring"("tenantId", "name");

-- CreateIndex
CREATE UNIQUE INDEX "Ring_tenantId_wsusGroup_key" ON "Ring"("tenantId", "wsusGroup");

-- CreateIndex
CREATE UNIQUE INDEX "Ring_tenantId_order_key" ON "Ring"("tenantId", "order");

-- CreateIndex
CREATE INDEX "User_tenantId_idx" ON "User"("tenantId");

-- AddForeignKey
ALTER TABLE "User" ADD CONSTRAINT "User_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Ring" ADD CONSTRAINT "Ring_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "MaintenanceWindow" ADD CONSTRAINT "MaintenanceWindow_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Endpoint" ADD CONSTRAINT "Endpoint_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Endpoint" ADD CONSTRAINT "Endpoint_connectorId_fkey" FOREIGN KEY ("connectorId") REFERENCES "Connector"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "EndpointPatchState" ADD CONSTRAINT "EndpointPatchState_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ChangeRequest" ADD CONSTRAINT "ChangeRequest_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Deployment" ADD CONSTRAINT "Deployment_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "InstalledSoftware" ADD CONSTRAINT "InstalledSoftware_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DiscoveredApp" ADD CONSTRAINT "DiscoveredApp_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Connector" ADD CONSTRAINT "Connector_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ConnectorEnrollment" ADD CONSTRAINT "ConnectorEnrollment_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ConnectorJob" ADD CONSTRAINT "ConnectorJob_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ConnectorJob" ADD CONSTRAINT "ConnectorJob_connectorId_fkey" FOREIGN KEY ("connectorId") REFERENCES "Connector"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "TenantApp" ADD CONSTRAINT "TenantApp_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "TenantApp" ADD CONSTRAINT "TenantApp_appId_fkey" FOREIGN KEY ("appId") REFERENCES "App"("id") ON DELETE RESTRICT ON UPDATE CASCADE;


-- Drop the temporary backfill defaults: new rows must always name their bank explicitly.
ALTER TABLE "ChangeRequest" ALTER COLUMN "tenantId" DROP DEFAULT;
ALTER TABLE "Deployment" ALTER COLUMN "tenantId" DROP DEFAULT;
ALTER TABLE "DiscoveredApp" ALTER COLUMN "tenantId" DROP DEFAULT;
ALTER TABLE "Endpoint" ALTER COLUMN "tenantId" DROP DEFAULT;
ALTER TABLE "EndpointPatchState" ALTER COLUMN "tenantId" DROP DEFAULT;
ALTER TABLE "InstalledSoftware" ALTER COLUMN "tenantId" DROP DEFAULT;
ALTER TABLE "MaintenanceWindow" ALTER COLUMN "tenantId" DROP DEFAULT;
ALTER TABLE "Ring" ALTER COLUMN "tenantId" DROP DEFAULT;
