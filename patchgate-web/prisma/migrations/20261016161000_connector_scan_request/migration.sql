-- "Request scan of all PCs" (Endpoints page): an offline Windows Update scan (WU_SCAN) was asked for this
-- site. The scheduler queues it after the requested agent sync has been applied (SYNC_AGENTS → SCAN → WU_SCAN),
-- once the verified scan catalog is cached at the site, and then clears the flag.
ALTER TABLE "Connector" ADD COLUMN IF NOT EXISTS "wuScanRequestedAt" TIMESTAMP(3);
