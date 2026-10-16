-- Security fix: the update -> files binding (and title/KB/severity) of Windows updates is AUTHORITATIVE from the
-- Microsoft Update Catalog, never from PC scan reports. PC reports only say WHICH update GUIDs apply.
-- Existing rows were bound from PC reports: every update goes back to PENDING (re-validated against the
-- catalog by the fetch loop) and every existing file is marked REPORTED (never planned for install again;
-- reconciled / removed when its update resolves).

-- CreateEnum
CREATE TYPE "WinUpdateCatalogState" AS ENUM ('PENDING', 'RESOLVED', 'UNRESOLVABLE');
CREATE TYPE "WinUpdateFileSource" AS ENUM ('REPORTED', 'CATALOG');

-- AlterTable
ALTER TABLE "WinUpdate" ADD COLUMN "catalogState" "WinUpdateCatalogState" NOT NULL DEFAULT 'PENDING',
ADD COLUMN "nextResolveAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
ADD COLUMN "resolveAttempts" INTEGER NOT NULL DEFAULT 0,
ADD COLUMN "resolveError" TEXT,
ADD COLUMN "resolvedAt" TIMESTAMP(3);

ALTER TABLE "WinUpdateFile" ADD COLUMN "source" "WinUpdateFileSource" NOT NULL DEFAULT 'REPORTED';

-- Bank "Manage" of a product not on the shared allow-list: a request for a PatchGate platform admin.
ALTER TABLE "DiscoveredApp" ADD COLUMN "requestedAt" TIMESTAMP(3),
ADD COLUMN "requestedBy" TEXT;

-- CreateIndex
CREATE INDEX "WinUpdate_catalogState_nextResolveAt_idx" ON "WinUpdate"("catalogState", "nextResolveAt");
CREATE INDEX "DiscoveredApp_requestedAt_idx" ON "DiscoveredApp"("requestedAt");

-- Re-validate: metadata reported by PCs is not trusted any more.
UPDATE "WinUpdate" SET "catalogState" = 'PENDING', "nextResolveAt" = CURRENT_TIMESTAMP;
-- Not-yet-downloaded reported files are dropped (nothing on disk); verified ones stay REPORTED until reconciled.
DELETE FROM "WinUpdateFile" WHERE "verification" <> 'VERIFIED';

-- Metadata of a resolved update is immutable (it was set from the authoritative source exactly once).
CREATE OR REPLACE FUNCTION patchgate_winupdate_immutable() RETURNS trigger AS $$
BEGIN
  IF OLD."catalogState" = 'RESOLVED' AND (
       NEW."catalogState" IS DISTINCT FROM OLD."catalogState"
    OR NEW."kb" IS DISTINCT FROM OLD."kb"
    OR NEW."title" IS DISTINCT FROM OLD."title"
    OR NEW."msrcSeverity" IS DISTINCT FROM OLD."msrcSeverity"
    OR NEW."classification" IS DISTINCT FROM OLD."classification") THEN
    RAISE EXCEPTION 'WinUpdate % is resolved from the Microsoft Update Catalog: metadata is immutable', OLD."id";
  END IF;
  RETURN NEW;
END
$$ LANGUAGE plpgsql;

CREATE TRIGGER "WinUpdate_immutable" BEFORE UPDATE ON "WinUpdate"
  FOR EACH ROW EXECUTE FUNCTION patchgate_winupdate_immutable();

-- A catalog-bound file keeps its binding (update, URL, expected digests, order) forever, and no file can be
-- added to an update whose binding is already sealed (RESOLVED / UNRESOLVABLE).
CREATE OR REPLACE FUNCTION patchgate_winupdate_file_binding() RETURNS trigger AS $$
DECLARE
  st "WinUpdateCatalogState";
BEGIN
  IF TG_OP = 'INSERT' THEN
    SELECT "catalogState" INTO st FROM "WinUpdate" WHERE "id" = NEW."updateId";
    IF NEW."source" <> 'CATALOG' THEN
      RAISE EXCEPTION 'WinUpdateFile: only Microsoft Update Catalog bindings may be added';
    END IF;
    IF st IS DISTINCT FROM 'PENDING' THEN
      RAISE EXCEPTION 'WinUpdateFile: binding of update % is sealed', NEW."updateId";
    END IF;
    RETURN NEW;
  END IF;
  IF OLD."source" = 'CATALOG' AND (
       NEW."source" IS DISTINCT FROM OLD."source"
    OR NEW."updateId" IS DISTINCT FROM OLD."updateId"
    OR NEW."url" IS DISTINCT FROM OLD."url"
    OR NEW."sha1" IS DISTINCT FROM OLD."sha1"
    OR NEW."expectedSha256" IS DISTINCT FROM OLD."expectedSha256"
    OR NEW."ordinal" IS DISTINCT FROM OLD."ordinal") THEN
    RAISE EXCEPTION 'WinUpdateFile %: catalog binding is immutable', OLD."id";
  END IF;
  IF OLD."source" = 'REPORTED' AND NEW."source" = 'CATALOG' THEN
    SELECT "catalogState" INTO st FROM "WinUpdate" WHERE "id" = NEW."updateId";
    IF st IS DISTINCT FROM 'PENDING' THEN
      RAISE EXCEPTION 'WinUpdateFile: binding of update % is sealed', NEW."updateId";
    END IF;
  END IF;
  RETURN NEW;
END
$$ LANGUAGE plpgsql;

CREATE TRIGGER "WinUpdateFile_binding" BEFORE INSERT OR UPDATE ON "WinUpdateFile"
  FOR EACH ROW EXECUTE FUNCTION patchgate_winupdate_file_binding();
