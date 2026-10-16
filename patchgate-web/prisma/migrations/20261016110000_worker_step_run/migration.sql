-- Worker step summary for monitoring (/api/metrics, /operations): one row per tick step, upserted by the
-- tick route after every run. Platform-level data (no tenantId) — no Row-Level Security.
CREATE TABLE IF NOT EXISTS "WorkerStepRun" (
    "step" TEXT NOT NULL,
    "lastRunAt" TIMESTAMP(3) NOT NULL,
    "lastDurationMs" INTEGER NOT NULL,
    "lastOk" BOOLEAN NOT NULL,
    "lastStatus" TEXT NOT NULL,
    "lastSuccessAt" TIMESTAMP(3),
    "lastFailureAt" TIMESTAMP(3),
    "runs" BIGINT NOT NULL DEFAULT 0,
    "failures" BIGINT NOT NULL DEFAULT 0,
    "totalDurationMs" BIGINT NOT NULL DEFAULT 0,

    CONSTRAINT "WorkerStepRun_pkey" PRIMARY KEY ("step")
);

-- Usable inside withPlatform() (SET LOCAL ROLE patchgate_tenant) like every other table.
GRANT SELECT, INSERT, UPDATE, DELETE ON "WorkerStepRun" TO patchgate_tenant;
