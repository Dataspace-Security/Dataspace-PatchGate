-- AlterTable
ALTER TABLE "Deployment" ADD COLUMN     "claimedAt" TIMESTAMP(3);

-- AlterTable
ALTER TABLE "Endpoint" ADD COLUMN     "ingestAttemptAt" TIMESTAMP(3);

-- CreateTable
CREATE TABLE "WorkerLease" (
    "name" TEXT NOT NULL,
    "holder" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "WorkerLease_pkey" PRIMARY KEY ("name")
);
