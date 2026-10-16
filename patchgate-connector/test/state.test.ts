import { appendFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { CacheIndex, type CacheEntry } from "../src/cache/cache-index.ts";
import { Journal } from "../src/journal.ts";
import { tempDir } from "./helpers/common.ts";

let dir: string;
let cleanup: () => Promise<void>;
beforeEach(async () => {
  ({ dir, cleanup } = await tempDir());
});
afterEach(async () => cleanup());

describe("Journal (idempotency + durability)", () => {
  it("records start/done/posted and survives a reopen", async () => {
    const file = join(dir, "journal.jsonl");
    const j = await Journal.open(file, { retentionDays: 30 });
    await j.markStarted("job1", "SCAN");
    await j.markDone("job1", "SCAN", { ok: true, result: { requested: [], failed: [] } });
    await j.markStarted("job2", "DEPLOY_PACKAGE");
    await j.close();

    const j2 = await Journal.open(file, { retentionDays: 30 });
    expect(j2.get("job1")?.result).toEqual({ ok: true, result: { requested: [], failed: [] } });
    expect(j2.unposted().map((s) => s.jobId)).toEqual(["job1"]);
    expect(j2.get("job2")).toMatchObject({ startedAt: expect.any(String) });
    expect(j2.get("job2")?.result).toBeUndefined();
    await j2.markPosted("job1", "accepted");
    expect(j2.unposted()).toEqual([]);
    await j2.close();
  });

  it("first recorded result wins", async () => {
    const j = await Journal.open(join(dir, "j.jsonl"), { retentionDays: 30 });
    const first = await j.markDone("a", "SCAN", { ok: false, error: "x", retryable: true });
    const second = await j.markDone("a", "SCAN", { ok: true, result: {} });
    expect(second).toEqual(first);
    expect(j.get("a")?.result).toEqual(first);
    await j.close();
  });

  it("skips a torn last line and compacts old acknowledged jobs", async () => {
    const file = join(dir, "j.jsonl");
    const old = new Date(Date.now() - 40 * 86_400_000).toISOString();
    const lines = [
      { t: "done", jobId: "old", type: "SCAN", at: old, result: { ok: true, result: {} } },
      { t: "posted", jobId: "old", at: old, outcome: "accepted" },
      { t: "done", jobId: "fresh", type: "SCAN", at: new Date().toISOString(), result: { ok: true, result: {} } },
    ];
    await writeFile(file, lines.map((l) => JSON.stringify(l)).join("\n") + "\n");
    await appendFile(file, '{"t":"done","jobId":"torn"'); // power cut mid-write
    const j = await Journal.open(file, { retentionDays: 30 });
    expect(j.skippedLines).toBe(1);
    expect(j.get("old")).toBeUndefined();
    expect(j.get("fresh")?.result).toBeDefined();
    await j.close();
    const text = await readFile(file, "utf8");
    expect(text).not.toContain("old");
    expect(text).not.toContain("torn");
  });

  it("serialises concurrent appends", async () => {
    const file = join(dir, "j.jsonl");
    const j = await Journal.open(file, { retentionDays: 30 });
    await Promise.all(Array.from({ length: 50 }, (_, i) => j.markDone(`job${i}`, "SCAN", { ok: true, result: { i } })));
    await j.close();
    const j2 = await Journal.open(file, { retentionDays: 30 });
    expect(j2.size).toBe(50);
    expect(j2.skippedLines).toBe(0);
    await j2.close();
  });
});

describe("CacheIndex", () => {
  const write = async (root: string, rel: string, bytes: Buffer): Promise<CacheEntry> => {
    const p = join(root, rel);
    await mkdir(dirname(p), { recursive: true });
    await writeFile(p, bytes);
    return {
      repoPath: rel,
      sha256: createHash("sha256").update(bytes).digest("hex"),
      size: bytes.length,
      kind: "msi",
      wingetId: "a.b",
      version: "1.0",
      cachedAt: new Date().toISOString(),
    };
  };

  it("persists entries, verifies hashes, and drops missing/changed files on reopen", async () => {
    const root = join(dir, "cache");
    const idxFile = join(dir, "cache-index.json");
    const idx = await CacheIndex.open(idxFile, root);
    const e1 = await write(root, "pkgs/a/1.0/a.msi", Buffer.from("hello"));
    const e2 = await write(root, "pkgs/b/1.0/b.msi", Buffer.from("world"));
    await idx.put(e1);
    await idx.put(e2);
    expect(idx.stats()).toEqual({ files: 2, bytes: 10 });
    expect(await idx.verify(e1.repoPath)).toBe(true);

    await writeFile(join(root, e1.repoPath), "HELLO"); // same size, different bytes
    // a fresh process (no verification memo) re-hashes and notices the tampering
    const fresh = await CacheIndex.open(idxFile, root);
    expect(await fresh.verify(e1.repoPath)).toBe(false);

    await writeFile(join(root, e2.repoPath), "longer content"); // size changed
    const reopened = await CacheIndex.open(idxFile, root);
    expect(reopened.get(e2.repoPath)).toBeUndefined();
    expect(reopened.get(e1.repoPath)).toBeDefined(); // size unchanged: kept until a deploy re-hashes it

    await reopened.remove(e1.repoPath);
    expect(reopened.get(e1.repoPath)).toBeUndefined();
    const again = await CacheIndex.open(idxFile, root);
    expect(again.list()).toEqual([]);
  });

  it("refuses unsafe repo paths", async () => {
    const idx = await CacheIndex.open(join(dir, "i.json"), join(dir, "cache"));
    await expect(idx.put({ repoPath: "../x", sha256: "a".repeat(64), size: 1, kind: "msi", wingetId: "a", version: "1", cachedAt: "" })).rejects.toThrow();
  });
});
