import { createHash } from "node:crypto";
import { request as httpRequest, type IncomingMessage } from "node:http";
import { mkdir, symlink, writeFile } from "node:fs/promises";
import { connect } from "node:net";
import { dirname, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { CacheIndex } from "../src/cache/cache-index.ts";
import { CacheServer } from "../src/cache/server.ts";
import { silentLogger } from "../src/util/log.ts";
import { TokenBucket } from "../src/util/token-bucket.ts";
import { tempDir } from "./helpers/common.ts";

let dir: string;
let cleanup: () => Promise<void>;
let index: CacheIndex;
let root: string;
let server: CacheServer | undefined;
let port = 0;
const BIG = Buffer.alloc(512 * 1024, 7);
const REL = "pkgs/app/1.0/app.msi";

async function addFile(rel: string, bytes: Buffer): Promise<void> {
  const p = join(root, rel);
  await mkdir(dirname(p), { recursive: true });
  await writeFile(p, bytes);
  await index.put({ repoPath: rel, sha256: createHash("sha256").update(bytes).digest("hex"), size: bytes.length, kind: "msi", wingetId: "a.b", version: "1.0", cachedAt: "" });
}

async function startServer(over: Partial<ConstructorParameters<typeof CacheServer>[0]> = {}): Promise<void> {
  server = new CacheServer({
    root,
    index,
    prefix: "/repo",
    host: "127.0.0.1",
    port: 0,
    maxConcurrentDownloads: 50,
    perClientConcurrency: 2,
    retryAfterSec: 30,
    bucket: new TokenBucket(null),
    log: silentLogger,
    ...over,
  });
  port = (await server.start()).port;
}

interface Resp {
  status: number;
  headers: IncomingMessage["headers"];
  body: Buffer;
}

function get(path: string, method = "GET", headers: Record<string, string> = {}): Promise<Resp> {
  return new Promise((resolve, reject) => {
    const req = httpRequest({ host: "127.0.0.1", port, path, method, headers, agent: false }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks) }));
      res.on("error", reject);
    });
    req.on("error", reject);
    req.end();
  });
}

/** Raw request line, so the path is sent exactly as written (no client-side normalisation). */
function rawGet(path: string): Promise<number> {
  return new Promise((resolve, reject) => {
    const s = connect(port, "127.0.0.1", () => s.write(`GET ${path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n`));
    let data = "";
    s.on("data", (d) => (data += d.toString()));
    s.on("end", () => resolve(Number(/^HTTP\/1\.1 (\d{3})/.exec(data)?.[1] ?? 0)));
    s.on("error", reject);
  });
}

/** Start a GET and resolve once headers arrive; the body keeps streaming (slot stays busy). */
function openDownload(path: string): Promise<{ status: number; headers: IncomingMessage["headers"]; done: Promise<number> }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest({ host: "127.0.0.1", port, path, agent: false }, (res) => {
      let n = 0;
      const done = new Promise<number>((r) => {
        res.on("data", (c: Buffer) => (n += c.length));
        res.on("end", () => r(n));
      });
      resolve({ status: res.statusCode ?? 0, headers: res.headers, done });
    });
    req.on("error", reject);
    req.end();
  });
}

beforeEach(async () => {
  ({ dir, cleanup } = await tempDir());
  root = join(dir, "cache");
  index = await CacheIndex.open(join(dir, "idx.json"), root);
  await addFile(REL, BIG);
});
afterEach(async () => {
  await server?.stop();
  server = undefined;
  await cleanup();
});

describe("cache server: what it serves", () => {
  it("serves indexed files with hash headers; HEAD and Range work", async () => {
    await startServer();
    const r = await get(`/repo/${REL}`);
    expect(r.status).toBe(200);
    expect(r.body.equals(BIG)).toBe(true);
    expect(r.headers["x-content-sha256"]).toBe(createHash("sha256").update(BIG).digest("hex"));
    const h = await get(`/repo/${REL}`, "HEAD");
    expect(h.status).toBe(200);
    expect(h.headers["content-length"]).toBe(String(BIG.length));
    expect(h.body.length).toBe(0);
    const part = await get(`/repo/${REL}`, "GET", { range: "bytes=10-19" });
    expect(part.status).toBe(206);
    expect(part.body.length).toBe(10);
    expect(part.headers["content-range"]).toBe(`bytes 10-19/${BIG.length}`);
    expect((await get(`/repo/${REL}`, "GET", { range: "bytes=999999999-" })).status).toBe(416);
  });

  it("refuses unknown paths, traversal, encoded tricks, listings and other methods", async () => {
    await mkdir(join(root, "pkgs/app/2.0"), { recursive: true });
    await writeFile(join(root, "pkgs/app/2.0/unindexed.msi"), "not verified");
    await writeFile(join(dir, "secret.txt"), "secret");
    await startServer();
    expect((await get("/repo/pkgs/app/2.0/unindexed.msi")).status).toBe(404); // on disk but not verified
    expect((await get("/repo/pkgs/app/1.0/")).status).toBe(404); // no listing
    expect((await get("/repo/")).status).toBe(404);
    expect((await get(`/${REL}`)).status).toBe(404); // outside the prefix
    for (const p of ["/repo/pkgs/../../secret.txt", "/repo/pkgs/%2e%2e/%2e%2e/secret.txt", "/repo/pkgs/app/1.0/app.msi%00", "/repo/pkgs\\app\\1.0\\app.msi", "/repo//etc/passwd", "/repo/../idx.json"]) {
      expect(await rawGet(p)).toBe(404);
    }
    for (const m of ["POST", "PUT", "DELETE", "OPTIONS"]) expect((await get(`/repo/${REL}`, m)).status).toBe(405);
    const health = await get("/healthz");
    expect(health.status).toBe(200);
    expect(JSON.parse(health.body.toString())).toMatchObject({ status: "ok", files: 1 });
  });

  it("does not follow a symlink planted inside the cache to a file outside it", async () => {
    await writeFile(join(dir, "outside.bin"), "outside");
    const rel = "pkgs/evil/1.0/evil.msi";
    await mkdir(join(root, "pkgs/evil/1.0"), { recursive: true });
    try {
      await symlink(join(dir, "outside.bin"), join(root, rel));
    } catch {
      return; // creating symlinks needs privileges on Windows; covered on Linux CI
    }
    await index.put({ repoPath: rel, sha256: "a".repeat(64), size: 7, kind: "msi", wingetId: "a.b", version: "1.0", cachedAt: "" });
    await startServer();
    expect((await get(`/repo/${rel}`)).status).toBe(404);
  });
});

describe("cache server: network protection", () => {
  it("caps concurrent downloads globally with 503 + Retry-After", async () => {
    await startServer({ maxConcurrentDownloads: 2, perClientConcurrency: 10, bucket: new TokenBucket(1_000_000) });
    const a = await openDownload(`/repo/${REL}`);
    const b = await openDownload(`/repo/${REL}`);
    expect([a.status, b.status]).toEqual([200, 200]);
    const c = await get(`/repo/${REL}`);
    expect(c.status).toBe(503);
    expect(c.headers["retry-after"]).toBe("30");
    expect(server!.stats()).toMatchObject({ activeDownloads: 2, rejectedBusy: 1 });
    expect(await a.done).toBe(BIG.length);
    await b.done;
    await new Promise((r) => setTimeout(r, 50));
    expect(server!.stats().activeDownloads).toBe(0);
    expect((await get(`/repo/${REL}`)).status).toBe(200); // slots freed
  });

  it("caps concurrent downloads per client IP", async () => {
    await startServer({ maxConcurrentDownloads: 50, perClientConcurrency: 1, bucket: new TokenBucket(1_000_000) });
    const a = await openDownload(`/repo/${REL}`);
    expect(a.status).toBe(200);
    expect((await get(`/repo/${REL}`)).status).toBe(503);
    await a.done;
  });

  it("shares one bandwidth limit across all downloads and applies live rate changes", async () => {
    const bucket = new TokenBucket(1_000_000); // 1 MB/s total (8 Mbit/s), 250 kB burst
    await startServer({ bucket });
    let t0 = Date.now();
    const [x, y] = await Promise.all([openDownload(`/repo/${REL}`), openDownload(`/repo/${REL}`)]);
    await Promise.all([x.done, y.done]);
    const limited = Date.now() - t0;
    // 1 MiB total at 1 MB/s minus the burst: at least ~0.75 s, regardless of the number of clients
    expect(limited).toBeGreaterThanOrEqual(650);

    bucket.setRate(null); // e.g. heartbeat lifted the limit
    t0 = Date.now();
    const [p, q] = await Promise.all([openDownload(`/repo/${REL}`), openDownload(`/repo/${REL}`)]);
    await Promise.all([p.done, q.done]);
    expect(Date.now() - t0).toBeLessThan(limited);
  });
});
