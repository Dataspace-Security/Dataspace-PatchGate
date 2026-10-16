-- Real-time Tactical guard (connector protocol §8): signed allow-set baseline job for the connector's approval guard.
-- Additive only. Pushed guard reports reuse "TacticalActivity" (source APPROVAL_GUARD; the column is free text).
ALTER TYPE "ConnectorJobType" ADD VALUE IF NOT EXISTS 'TACTICAL_GUARD_SYNC';
