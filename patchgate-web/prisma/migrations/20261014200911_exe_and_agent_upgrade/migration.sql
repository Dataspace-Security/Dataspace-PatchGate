-- CreateEnum
CREATE TYPE "InstallerKind" AS ENUM ('MSI', 'EXE');

-- AlterEnum
ALTER TYPE "PatchKind" ADD VALUE 'AGENT_UPGRADE';

-- AlterTable
ALTER TABLE "AppVersion" ADD COLUMN     "installerKind" "InstallerKind" NOT NULL DEFAULT 'MSI',
ADD COLUMN     "installerType" TEXT NOT NULL DEFAULT 'msi';

-- AlterTable
ALTER TABLE "Endpoint" ADD COLUMN     "agentVersion" TEXT,
ADD COLUMN     "goarch" TEXT;

-- AlterTable
ALTER TABLE "Patch" ADD COLUMN     "agentVersion" TEXT;
