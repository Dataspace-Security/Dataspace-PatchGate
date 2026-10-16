import { createHash } from "node:crypto";
import { mkdir, readdir, readFile, stat, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { CacheDownloader } from "../src/cache/download.ts";
import { CacheIndex } from "../src/cache/cache-index.ts";
import { JobError } from "../src/jobs/errors.ts";
import { Journal } from "../src/journal.ts";
import { silentLogger } from "../src/util/log.ts";
import { tempDir } from "./helpers/common.ts";

let dir: string;
let cleanup: () => Promise<void>;
beforeEach(async () => {
  ({ dir, cleanup } = await tempDir());
});
afterEach(async () => cleanup());

describe("H6: bounded journal", () => {
  const bigCollect = (n: number) => ({ ok: true as const, result: { agents: [{ agentId: "agentAAAA0001", software: Array.from({ length: n }, (_, i) => ({ name: `app${i}`, version: "1" })) }] } });

  it("never journals read-only bodies; drops install bodies once acknowledged; keeps a dedupe stub", async () => {
    const file = join(dir, "j.jsonl");
    const j = await Journal.open(file, { retentionDays: 30 });
    await j.markStarted("c1", "COLLECT");
    await j.markDone("c1", "COLLECT", bigCollect(2000), { keepBody: false });
    await j.markStarted("d1", "DEPLOY_PACKAGE", new Date(Date.now() + 3_600_000).toISOString());
    await j.markDone("d1", "DEPLOY_PACKAGE", { ok: true, result: { outcome: "INSTALLED", output: "x".repeat(1500) } });
    expect(await readFile(file, "utf8")).not.toContain("app1999");
    expect(j.get("d1")?.result).toBeDefined(); // unposted: body kept for re-posting
    await j.markPosted("d1", "accepted");
    expect(j.get("d1")?.result).toBeUndefined();
    expect(j.get("d1")).toMatchObject({ summary: { ok: true }, postOutcome: "accepted", startedAt: expect.any(String) });
    await j.close();

    const j2 = await Journal.open(file, { retentionDays: 30 });
    expect(await readFile(file, "utf8")).not.toContain("xxxxxxxxxx"); // compacted: body gone from disk
    expect(j2.get("d1")).toMatchObject({ summary: { ok: true }, postOutcome: "accepted" });
    expect(j2.get("c1")).toMatchObject({ summary: { ok: true }, doneAt: expect.any(String) });
    expect(j2.get("c1")?.result).toBeUndefined();
    expect(j2.unposted()).toEqual([]);
    await j2.close();
  });

  it("drops stubs once the signed job has expired (it can no longer be accepted), never an undelivered result", async () => {
    const file = join(dir, "j.jsonl");
    const j = await Journal.open(file, { retentionDays: 30 });
    const past = new Date(Date.now() - 3 * 3_600_000).toISOString();
    await j.markDone("old", "DEPLOY_PACKAGE", { ok: true, result: { outcome: "INSTALLED" } }, { expiresAt: past });
    await j.markPosted("old", "accepted");
    await j.markDone("live", "DEPLOY_PACKAGE", { ok: true, result: { outcome: "INSTALLED" } }, { expiresAt: new Date(Date.now() + 3_600_000).toISOString() });
    await j.markPosted("live", "accepted");
    await j.markDone("unposted", "DEPLOY_PACKAGE", { ok: true, result: { outcome: "INSTALLED" } }, { expiresAt: past });
    await j.close();
    const j2 = await Journal.open(file, { retentionDays: 30 });
    expect(j2.get("old")).toBeUndefined();
    expect(j2.get("live")).toBeDefined();
    expect(j2.get("unposted")?.result).toBeDefined();
    await j2.close();
  });

  it("compacts at runtime and enforces its size cap", async () => {
    const file = join(dir, "j.jsonl");
    const maxBytes = 20_000;
    const j = await Journal.open(file, { retentionDays: 30, maxBytes });
    const out = "y".repeat(500);
    for (let i = 0; i < 150; i++) {
      await j.markDone(`job${i}`, "DEPLOY_PACKAGE", { ok: true, result: { outcome: "INSTALLED", output: out } });
      await j.markPosted(`job${i}`, "accepted");
    }
    await j.markDone("pending", "DEPLOY_PACKAGE", { ok: true, result: { outcome: "INSTALLED", output: out } });
    await j.compact();
    expect(j.stats.compactions).toBeGreaterThan(2);
    expect(j.stats.evicted).toBeGreaterThan(0);
    expect((await stat(file)).size).toBeLessThanOrEqual(maxBytes);
    expect(j.get("job0")).toBeUndefined(); // oldest acknowledged stub evicted first
    expect(j.get("job149")).toMatchObject({ postOutcome: "accepted" });
    expect(j.get("pending")?.result).toBeDefined(); // never an undelivered result
    await j.close();
  });
});

describe("M12: cache hygiene", () => {
  const put = async (idx: CacheIndex, root: string, rel: string, bytes: Buffer, cachedAt: string) => {
    const p = join(root, rel);
    await mkdir(dirname(p), { recursive: true });
    await writeFile(p, bytes);
    await idx.put({ repoPath: rel, sha256: createHash("sha256").update(bytes).digest("hex"), size: bytes.length, kind: "msi", wingetId: "a.b", version: "1.0", cachedAt });
  };

  it("evicts least-recently-used packages that no unexpired job pins and no PC is downloading", async () => {
    const root = join(dir, "cache");
    const idx = await CacheIndex.open(join(dir, "idx.json"), root);
    await put(idx, root, "pkgs/a/1/a.msi", Buffer.alloc(100, 1), "2026-01-01T00:00:00Z");
    await put(idx, root, "pkgs/b/1/b.msi", Buffer.alloc(100, 2), "2026-01-02T00:00:00Z");
    await put(idx, root, "pkgs/c/1/c.msi", Buffer.alloc(100, 3), "2026-01-03T00:00:00Z");
    await put(idx, root, "pkgs/d/1/d.msi", Buffer.alloc(100, 4), "2026-01-04T00:00:00Z");
    await idx.pin(["pkgs/a/1/a.msi"], Date.now() + 3_600_000); // a deploy job still needs it
    expect(idx.acquire("pkgs/b/1/b.msi")).toBe(true); // a PC is downloading b
    const r = await idx.evict({ now: Date.now(), maxBytes: 250, needBytes: 0, freeBytes: async () => null, minFreeBytes: 0 });
    expect(r.removed.map((e) => e.repoPath)).toEqual(["pkgs/c/1/c.msi", "pkgs/d/1/d.msi"]);
    expect(r.stillOver).toBe(false);
    expect(idx.get("pkgs/a/1/a.msi")).toBeDefined();
    const reopened = await CacheIndex.open(join(dir, "idx.json"), root); // pins are persisted
    expect(reopened.pinnedUntil("pkgs/a/1/a.msi")).toBeGreaterThan(Date.now());
    await idx.release("pkgs/b/1/b.msi");
  });

  it("never deletes a file while it is being served; deletes it when the last reader finishes", async () => {
    const root = join(dir, "cache");
    const idx = await CacheIndex.open(join(dir, "idx.json"), root);
    await put(idx, root, "pkgs/a/1/a.msi", Buffer.from("abc"), "2026-01-01T00:00:00Z");
    expect(idx.acquire("pkgs/a/1/a.msi")).toBe(true);
    await idx.remove("pkgs/a/1/a.msi");
    expect(idx.get("pkgs/a/1/a.msi")).toBeUndefined(); // no new downloads
    expect(await readFile(join(root, "pkgs/a/1/a.msi"), "utf8")).toBe("abc"); // the running one continues
    expect(idx.acquire("pkgs/a/1/a.msi")).toBe(false);
    await idx.release("pkgs/a/1/a.msi");
    await expect(stat(join(root, "pkgs/a/1/a.msi"))).rejects.toThrow();
  });

  it("sweeps stale partial downloads; refuses CACHE_PACKAGE permanently below the free-space floor", async () => {
    const root = join(dir, "cache");
    await mkdir(join(root, ".tmp"), { recursive: true });
    await writeFile(join(root, ".tmp", "0b6c-partial"), "half a package");
    const idx = await CacheIndex.open(join(dir, "idx.json"), root);
    const dl = new CacheDownloader({ pg: {} as never, index: idx, root, maxPackageBytes: 1 << 20, minFreeBytes: 500, freeBytes: async () => 1000, log: silentLogger });
    expect(await dl.sweepTmp()).toBe(1);
    expect(await readdir(join(root, ".tmp"))).toEqual([]);

    await put(idx, root, "pkgs/old/1/old.msi", Buffer.alloc(300, 1), "2026-01-01T00:00:00Z");
    await put(idx, root, "pkgs/pinned/1/p.msi", Buffer.alloc(300, 2), "2026-01-02T00:00:00Z");
    await idx.pin(["pkgs/pinned/1/p.msi"], Date.now() + 3_600_000);
    const pkg = { kind: "msi" as const, wingetId: "x.y", version: "1", sha256: "e".repeat(64), size: 900, repoPath: "pkgs/x/1/x.msi", publisher: "O=X", switches: "" };
    const err = await dl.cache(pkg).then(
      () => null,
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(JobError);
    expect((err as JobError).retryable).toBe(false);
    expect((err as JobError).message).toMatch(/below its floor/);
    expect(idx.get("pkgs/old/1/old.msi")).toBeUndefined(); // the unpinned package was evicted first
    expect(idx.get("pkgs/pinned/1/p.msi")).toBeDefined();
  });
});
