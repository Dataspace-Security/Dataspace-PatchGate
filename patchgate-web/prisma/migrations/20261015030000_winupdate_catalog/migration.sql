-- Windows updates through PatchGate: shared Microsoft catalog (offline scan cab, updates, verified files)
-- + per-PC reboot / scan state. The catalog tables are PLATFORM data (same for every bank): no tenantId, no RLS.
-- Per-bank applicability stays in EndpointPatchState (RLS).

-- AlterTable
ALTER TABLE "Endpoint" ADD COLUMN     "lastWuScanAt" TIMESTAMP(3),
ADD COLUMN     "lastWuScanError" TEXT,
ADD COLUMN     "rebootRequired" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "rebootRequiredAt" TIMESTAMP(3);

-- CreateTable
CREATE TABLE "WsusScanCab" (
    "id" TEXT NOT NULL,
    "sha256" TEXT NOT NULL,
    "sizeBytes" BIGINT NOT NULL,
    "sourceUrl" TEXT NOT NULL,
    "etag" TEXT,
    "lastModified" TEXT,
    "verification" "PackageVerification" NOT NULL DEFAULT 'PENDING',
    "rejectReason" TEXT,
    "signerSubject" TEXT,
    "repoPath" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "WsusScanCab_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "WinUpdate" (
    "id" TEXT NOT NULL,
    "revision" INTEGER NOT NULL,
    "kb" TEXT,
    "title" TEXT NOT NULL,
    "msrcSeverity" TEXT,
    "classification" TEXT,
    "firstTenantId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "WinUpdate_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "WinUpdateFile" (
    "id" TEXT NOT NULL,
    "updateId" TEXT NOT NULL,
    "url" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "declaredSize" BIGINT,
    "sha1" TEXT,
    "sha256" TEXT,
    "expectedSha256" TEXT,
    "sizeBytes" BIGINT,
    "verification" "PackageVerification" NOT NULL DEFAULT 'PENDING',
    "rejectReason" TEXT,
    "signerSubject" TEXT,
    "repoPath" TEXT,
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "nextAttemptAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastError" TEXT,
    "verifiedAt" TIMESTAMP(3),
    "availableAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "WinUpdateFile_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "WsusScanCab_sha256_key" ON "WsusScanCab"("sha256");

-- CreateIndex
CREATE INDEX "WsusScanCab_verification_createdAt_idx" ON "WsusScanCab"("verification", "createdAt");

-- CreateIndex
CREATE INDEX "WinUpdateFile_verification_nextAttemptAt_idx" ON "WinUpdateFile"("verification", "nextAttemptAt");

-- CreateIndex
CREATE UNIQUE INDEX "WinUpdateFile_updateId_url_key" ON "WinUpdateFile"("updateId", "url");

-- AddForeignKey
ALTER TABLE "WinUpdateFile" ADD CONSTRAINT "WinUpdateFile_updateId_fkey" FOREIGN KEY ("updateId") REFERENCES "WinUpdate"("id") ON DELETE CASCADE ON UPDATE CASCADE;


-- Usable inside withTenant()/withPlatform() (RLS role). Default privileges already cover tables created by the
-- migrating role; explicit grants keep this independent of who runs the migration.
GRANT SELECT, INSERT, UPDATE, DELETE ON "WsusScanCab", "WinUpdate", "WinUpdateFile" TO patchgate_tenant;
