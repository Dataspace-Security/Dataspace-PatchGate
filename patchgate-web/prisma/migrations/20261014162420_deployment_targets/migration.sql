-- AlterTable
ALTER TABLE "Deployment" ADD COLUMN     "note" TEXT,
ADD COLUMN     "targetGuids" TEXT[] DEFAULT ARRAY[]::TEXT[];
