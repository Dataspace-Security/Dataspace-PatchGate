-- Notification webhook URLs (they embed a secret token) are encrypted at rest with AUTH_ENC_KEY
-- (AES-256-GCM, src/lib/notify/webhook-store.ts; same keyring + rotation CLI as the TOTP secrets).
--  * "webhookUrlsEnc"    : sealed boxes "v1.<iv>.<tag>.<ct>.<kid>" (base64url + ".": never a ':' — enforced below)
--  * "webhookUrlsLegacy" : the former plaintext column, kept only until the data migration has drained it.
-- Data migration: SQL cannot encrypt (the key is not in the database). Existing plaintext URLs are moved into
-- "webhookUrlsEnc" by the app — every worker tick (notifyDeliver step), every settings change and the
-- AUTH_ENC_KEY rotation CLI (scripts/admin/rotate-auth-enc-key.ts). Until then they keep working as before.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'NotificationSetting' AND column_name = 'webhookUrls')
     AND NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'NotificationSetting' AND column_name = 'webhookUrlsLegacy') THEN
    ALTER TABLE "NotificationSetting" RENAME COLUMN "webhookUrls" TO "webhookUrlsLegacy";
  END IF;
END
$$;

ALTER TABLE "NotificationSetting" ADD COLUMN IF NOT EXISTS "webhookUrlsEnc" TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[];

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'NotificationSetting_webhookUrlsEnc_sealed') THEN
    ALTER TABLE "NotificationSetting" ADD CONSTRAINT "NotificationSetting_webhookUrlsEnc_sealed"
      CHECK (position(':' IN array_to_string("webhookUrlsEnc", '|')) = 0);
  END IF;
END
$$;
