-- Install order of the files of one Windows update (e.g. checkpoint cumulative update before the latest one)
ALTER TABLE "WinUpdateFile" ADD COLUMN "ordinal" INTEGER NOT NULL DEFAULT 0;
