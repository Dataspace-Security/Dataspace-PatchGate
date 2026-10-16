-- Windows updates through PatchGate (offline scan + cached Microsoft update files)
ALTER TYPE "ConnectorJobType" ADD VALUE 'WU_SCAN';
ALTER TYPE "ConnectorJobType" ADD VALUE 'WU_INSTALL';
