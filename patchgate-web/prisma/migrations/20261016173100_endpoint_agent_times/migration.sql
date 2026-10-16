-- Agent data correctness (2026-10-16): Endpoint.lastSeenAt now carries Tactical's last_seen (UTC, clamped on
-- clock skew) instead of the sync time; bootedAt carries Tactical's boot_time (null when unknown / implausible).
ALTER TABLE "Endpoint" ADD COLUMN IF NOT EXISTS "bootedAt" TIMESTAMP(3);
