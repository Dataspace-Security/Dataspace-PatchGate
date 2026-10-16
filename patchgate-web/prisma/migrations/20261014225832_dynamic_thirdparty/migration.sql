-- CreateEnum
CREATE TYPE "HoldReason" AS ENUM ('FIRST_SIGNER', 'SIGNER_CHANGED', 'HASH_DRIFT');

-- CreateEnum
CREATE TYPE "DiscoveryMatch" AS ENUM ('PRODUCT_CODE', 'NAME_PUBLISHER', 'NONE');

-- AlterEnum
ALTER TYPE "PackageVerification" ADD VALUE 'HELD';

-- AlterTable
ALTER TABLE "App" ADD COLUMN     "strictHosts" BOOLEAN NOT NULL DEFAULT false,
ALTER COLUMN "expectedPublisher" DROP NOT NULL;

-- AlterTable
ALTER TABLE "AppVersion" ADD COLUMN     "catalogSha256" TEXT,
ADD COLUMN     "decidedAt" TIMESTAMP(3),
ADD COLUMN     "decidedBy" TEXT,
ADD COLUMN     "fileVersion" TEXT,
ADD COLUMN     "holdReason" "HoldReason",
ADD COLUMN     "signerOrg" TEXT,
ADD COLUMN     "signerSubject" TEXT;

-- CreateTable
CREATE TABLE "InstalledSoftware" (
    "id" TEXT NOT NULL,
    "endpointId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "publisher" TEXT,
    "version" TEXT,
    "productCode" TEXT,
    "normName" TEXT NOT NULL,
    "normPublisher" TEXT,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "InstalledSoftware_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "DiscoveredApp" (
    "id" TEXT NOT NULL,
    "key" TEXT NOT NULL,
    "displayName" TEXT NOT NULL,
    "publisher" TEXT,
    "wingetId" TEXT,
    "match" "DiscoveryMatch" NOT NULL DEFAULT 'NONE',
    "endpointCount" INTEGER NOT NULL DEFAULT 0,
    "versions" TEXT[],
    "appId" TEXT,
    "ignored" BOOLEAN NOT NULL DEFAULT false,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "DiscoveredApp_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "InstalledSoftware_normName_idx" ON "InstalledSoftware"("normName");

-- CreateIndex
CREATE INDEX "InstalledSoftware_productCode_idx" ON "InstalledSoftware"("productCode");

-- CreateIndex
CREATE UNIQUE INDEX "InstalledSoftware_endpointId_name_version_key" ON "InstalledSoftware"("endpointId", "name", "version");

-- CreateIndex
CREATE UNIQUE INDEX "DiscoveredApp_key_key" ON "DiscoveredApp"("key");

-- CreateIndex
CREATE INDEX "DiscoveredApp_wingetId_idx" ON "DiscoveredApp"("wingetId");

-- AddForeignKey
ALTER TABLE "InstalledSoftware" ADD CONSTRAINT "InstalledSoftware_endpointId_fkey" FOREIGN KEY ("endpointId") REFERENCES "Endpoint"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DiscoveredApp" ADD CONSTRAINT "DiscoveredApp_appId_fkey" FOREIGN KEY ("appId") REFERENCES "App"("id") ON DELETE SET NULL ON UPDATE CASCADE;
