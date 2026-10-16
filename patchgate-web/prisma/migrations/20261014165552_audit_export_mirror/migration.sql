-- CreateEnum
CREATE TYPE "MirrorComponent" AS ENUM ('TACTICAL_AGENT', 'TACTICAL_SERVER');

-- CreateTable
CREATE TABLE "AuditAnchor" (
    "id" TEXT NOT NULL,
    "seq" BIGINT NOT NULL,
    "hash" TEXT NOT NULL,
    "eventCount" INTEGER NOT NULL,
    "exportedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "target" TEXT NOT NULL,

    CONSTRAINT "AuditAnchor_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "MirroredRelease" (
    "id" TEXT NOT NULL,
    "component" "MirrorComponent" NOT NULL,
    "version" TEXT NOT NULL,
    "assetName" TEXT NOT NULL,
    "sourceUrl" TEXT NOT NULL,
    "sha256" TEXT NOT NULL,
    "sizeBytes" BIGINT NOT NULL,
    "repoPath" TEXT NOT NULL,
    "verification" "PackageVerification" NOT NULL DEFAULT 'PENDING',
    "rejectReason" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "MirroredRelease_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "FetchRun" (
    "id" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "startedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "finishedAt" TIMESTAMP(3),
    "ok" BOOLEAN,
    "message" TEXT,

    CONSTRAINT "FetchRun_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "AuditAnchor_seq_idx" ON "AuditAnchor"("seq");

-- CreateIndex
CREATE UNIQUE INDEX "MirroredRelease_component_version_assetName_key" ON "MirroredRelease"("component", "version", "assetName");

-- Anchors are evidence too: append-only, same as AuditEvent.
CREATE TRIGGER "AuditAnchor_no_update_delete"
  BEFORE UPDATE OR DELETE ON "AuditAnchor"
  FOR EACH ROW EXECUTE FUNCTION patchgate_audit_immutable();

CREATE TRIGGER "AuditAnchor_no_truncate"
  BEFORE TRUNCATE ON "AuditAnchor"
  FOR EACH STATEMENT EXECUTE FUNCTION patchgate_audit_immutable();
