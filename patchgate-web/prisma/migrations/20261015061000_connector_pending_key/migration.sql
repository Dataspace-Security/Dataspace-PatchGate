-- Two-phase connector re-key: re-enrolment stores the new key as PENDING; it replaces the current key only
-- when it signs its first request (the old key keeps working until then — a refused init never locks a
-- working site out).
ALTER TABLE "Connector" ADD COLUMN IF NOT EXISTS "pendingPublicKey" TEXT,
ADD COLUMN IF NOT EXISTS "pendingKeyAt" TIMESTAMP(3);
