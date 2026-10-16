-- Per-bank Windows update source (hosted model default: through PatchGate, no WSUS).
DO $$ BEGIN
  CREATE TYPE "WindowsUpdateSource" AS ENUM ('PATCHGATE', 'WSUS');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
ALTER TABLE "Tenant" ADD COLUMN IF NOT EXISTS "windowsUpdateSource" "WindowsUpdateSource" NOT NULL DEFAULT 'PATCHGATE';
