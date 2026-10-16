-- Windows Update lock state per PC (reported by the WU_SCAN script; null = not reported yet)
ALTER TABLE "Endpoint" ADD COLUMN "wuLocked" BOOLEAN;
ALTER TABLE "Endpoint" ADD COLUMN "wuLockCheckedAt" TIMESTAMP(3);
ALTER TABLE "Endpoint" ADD COLUMN "wuLockDetail" JSONB;
