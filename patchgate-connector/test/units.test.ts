import { describe, expect, it } from "vitest";
import { cachePathPrefix, configSchema, ConfigError, parseConfig } from "../src/config.ts";
import { cacheAbsPath, isSafeRepoPath } from "../src/cache/paths.ts";
import { parseRange } from "../src/cache/server.ts";
import { parseArgs } from "../src/cli.ts";
import { assertDeployablePackage, compareVersions, isTransientInstallFailure, parseInstallResult } from "../src/jobs/package-input.ts";
import { formatSyslog, frameOctetCounting, parseSiemUrl } from "../src/siem/syslog.ts";
import { backoffDelay } from "../src/util/backoff.ts";
import { createLogger } from "../src/util/log.ts";
import { mapPool, Semaphore } from "../src/util/semaphore.ts";
import { TokenBucket, type Clock } from "../src/util/token-bucket.ts";
import type { JobPackage } from "../src/protocol.ts";

const baseRaw = () => ({
  stateDir: "/var/lib/patchgate-connector",
  tactical: { url: "https://rmm-api.bank.local", installScriptId: 7 },
  cache: { baseUrl: "https://pgcache.bank.local:8443/repo", tls: { certFile: "cache.pem", keyFile: "cache.key" } },
});

describe("config validation", () => {
  it("accepts a minimal config and applies defaults", () => {
    const c = parseConfig(baseRaw(), "/etc/patchgate-connector");
    expect(c.cache.maxConcurrentDownloads).toBe(50);
    expect(c.cache.perClientConcurrency).toBe(2);
    expect(c.limits.heartbeatIntervalSec).toBe(60);
    expect(c.limits.pollWaitSec).toBe(25);
    expect(c.cache.dir?.replace(/\\/g, "/")).toMatch(/var\/lib\/patchgate-connector\/cache$/);
    expect(c.cache.tls?.certFile.replace(/\\/g, "/")).toMatch(/etc\/patchgate-connector\/cache\.pem$/);
  });
  it("rejects http PatchGate / Tactical / cache URLs unless insecureDev", () => {
    expect(() => parseConfig({ ...baseRaw(), server: { url: "http://pg.example.com" } }, "/")).toThrow(ConfigError);
    expect(() => parseConfig({ ...baseRaw(), tactical: { url: "http://rmm" } }, "/")).toThrow(/Tactical URL/);
    expect(() => parseConfig({ ...baseRaw(), cache: { baseUrl: "http://pgcache:8080/repo", tls: { certFile: "a", keyFile: "b" } } }, "/")).toThrow(/baseUrl/);
    expect(() => parseConfig({ ...baseRaw(), insecureDev: true, server: { url: "http://pg.example.com" }, tactical: { url: "http://rmm" } }, "/")).not.toThrow();
  });
  it("rejects a cache baseUrl the install script would refuse (trailing slash, query, odd chars)", () => {
    for (const baseUrl of ["https://pgcache/repo/", "https://pgcache/repo?x=1", "https://pg cache/repo", "https://user@pgcache/repo"]) {
      expect(configSchema.safeParse({ ...baseRaw(), cache: { ...baseRaw().cache, baseUrl } }).success).toBe(false);
    }
  });
  it("requires cache TLS, tls:// SIEM, and rejects unknown keys", () => {
    expect(() => parseConfig({ ...baseRaw(), cache: { baseUrl: "https://pgcache/repo" } }, "/")).toThrow(/cache\.tls/);
    expect(() => parseConfig({ ...baseRaw(), siem: { url: "tcp://siem:514" } }, "/")).toThrow(/tls/);
    expect(() => parseConfig({ ...baseRaw(), siem: { url: "udp://siem:514" } }, "/")).toThrow();
    expect(() => parseConfig({ ...baseRaw(), surprise: 1 }, "/")).toThrow();
  });
  it("rejects invalid limit values", () => {
    expect(() => parseConfig({ ...baseRaw(), cache: { ...baseRaw().cache, maxConcurrentDownloads: 0 } }, "/")).toThrow();
    expect(() => parseConfig({ ...baseRaw(), limits: { pollWaitSec: 60 } }, "/")).toThrow();
  });
  it("derives the served URL prefix from baseUrl", () => {
    expect(cachePathPrefix("https://pgcache:8443/repo")).toBe("/repo");
    expect(cachePathPrefix("https://pgcache:8443")).toBe("");
  });
});

describe("cache path safety", () => {
  it.each(["pkgs/7zip/24.08/7z2408-x64.msi", "tactical/agent/2.11.0/tacticalagent-v2.11.0-windows-amd64.exe"])("accepts %s", (p) => {
    expect(isSafeRepoPath(p)).toBe(true);
  });
  it.each([
    "../etc/passwd",
    "pkgs/../../etc/passwd",
    "pkgs/./a.msi",
    "pkgs/.tmp/x",
    "pkgs/a.msi.",
    "/pkgs/a.msi",
    "pkgs\\a.msi",
    "pkgs/a%2e%2e/b",
    "other/a.msi",
    "pkgs",
    "pkgs//a.msi",
    "pkgs/a b.msi",
    `pkgs/${"a/".repeat(10)}x.msi`,
  ])("rejects %s", (p) => {
    expect(isSafeRepoPath(p)).toBe(false);
    expect(() => cacheAbsPath("/cache", p)).toThrow();
  });
});

describe("Semaphore", () => {
  it("limits concurrency and honours runtime capacity changes", async () => {
    const s = new Semaphore(2);
    let active = 0;
    let peak = 0;
    const task = () =>
      s.run(async () => {
        active++;
        peak = Math.max(peak, active);
        await new Promise((r) => setTimeout(r, 10));
        active--;
      });
    await Promise.all(Array.from({ length: 8 }, task));
    expect(peak).toBe(2);
    s.setCapacity(4);
    peak = 0;
    await Promise.all(Array.from({ length: 8 }, task));
    expect(peak).toBe(4);
  });
  it("lowering capacity does not interrupt holders and gates new ones", async () => {
    const s = new Semaphore(3);
    await s.acquire();
    await s.acquire();
    s.setCapacity(1);
    expect(s.tryAcquire()).toBe(false);
    s.release();
    expect(s.tryAcquire()).toBe(false);
    s.release();
    expect(s.tryAcquire()).toBe(true);
  });
  it("an aborted waiter takes no permit", async () => {
    const s = new Semaphore(1);
    await s.acquire();
    const ac = new AbortController();
    const p = s.acquire(ac.signal);
    ac.abort();
    await expect(p).rejects.toThrow();
    s.release();
    expect(s.inUse).toBe(0);
    expect(s.tryAcquire()).toBe(true);
  });
  it("mapPool keeps order and the limit", async () => {
    let active = 0;
    let peak = 0;
    const out = await mapPool([1, 2, 3, 4, 5, 6], 2, async (n) => {
      active++;
      peak = Math.max(peak, active);
      await new Promise((r) => setTimeout(r, 5));
      active--;
      return n * 10;
    });
    expect(out).toEqual([10, 20, 30, 40, 50, 60]);
    expect(peak).toBe(2);
  });
});

describe("TokenBucket", () => {
  const fakeClock = () => {
    let t = 0;
    const sleeps: number[] = [];
    const clock: Clock = {
      now: () => t,
      sleep: async (ms) => {
        sleeps.push(ms);
        t += ms;
      },
    };
    return { clock, sleeps, advance: (ms: number) => (t += ms) };
  };

  it("lets a burst through, then paces to the configured rate", async () => {
    const { clock, sleeps } = fakeClock();
    const b = new TokenBucket(100_000, clock, 0.25); // 100 kB/s, burst 25 kB
    await b.take(25_000);
    expect(sleeps).toEqual([]);
    await b.take(50_000); // 0.5 s of debt
    expect(sleeps).toEqual([500]);
  });
  it("is shared: concurrent takers queue in aggregate", async () => {
    const sleeps: number[] = [];
    const frozen: Clock = { now: () => 0, sleep: async (ms) => void sleeps.push(ms) }; // all callers arrive at t=0
    const b = new TokenBucket(100_000, frozen, 0.1); // burst = 16 KiB minimum
    await Promise.all([b.take(16_000), b.take(50_000), b.take(50_000)]);
    // the second waits ~0.5 s, the third ~1.0 s: its tokens come after the second's
    expect(sleeps).toEqual([497, 997]);
  });
  it("supports live rate changes and unlimited", async () => {
    const { clock, sleeps } = fakeClock();
    const b = new TokenBucket(null, clock);
    await b.take(10_000_000);
    expect(sleeps).toEqual([]);
    b.setRate(1_000_000);
    await b.take(1_250_000); // burst 250 kB, 1 s debt
    expect(sleeps).toEqual([1000]);
    expect(() => b.setRate(0)).toThrow();
  });
});

describe("misc helpers", () => {
  it("backoff grows exponentially with jitter, capped", () => {
    const lo = { baseMs: 1000, maxMs: 60_000, random: () => 0 };
    const hi = { baseMs: 1000, maxMs: 60_000, random: () => 1 };
    expect(backoffDelay(0, hi)).toBe(1000);
    expect(backoffDelay(3, hi)).toBe(8000);
    expect(backoffDelay(30, hi)).toBe(60_000);
    expect(backoffDelay(5, lo)).toBe(500);
  });
  it("parses Range headers", () => {
    expect(parseRange(undefined, 100)).toBeNull();
    expect(parseRange("bytes=0-9", 100)).toEqual({ start: 0, end: 9 });
    expect(parseRange("bytes=90-", 100)).toEqual({ start: 90, end: 99 });
    expect(parseRange("bytes=-10", 100)).toEqual({ start: 90, end: 99 });
    expect(parseRange("bytes=100-", 100)).toBe("invalid");
    expect(parseRange("bytes=0-1,5-6", 100)).toBeNull();
    expect(parseRange("items=0-1", 100)).toBe("invalid");
  });
  it("formats RFC 5424 with octet counting", () => {
    const line = formatSyslog({ ts: new Date("2026-10-15T10:00:00Z"), hostname: "conn 1", msgId: "AUDIT", sd: { seq: "5", hash: 'a"b]' }, msg: "x\ny" });
    expect(line).toBe('<110>1 2026-10-15T10:00:00.000Z conn1 patchgate - AUDIT [patchgate@32473 seq="5" hash="a\\"b\\]"] x y');
    expect(frameOctetCounting("abc")).toBe("3 abc");
    expect(parseSiemUrl("tls://siem.bank.local:6514")).toEqual({ protocol: "tls", host: "siem.bank.local", port: 6514 });
    expect(() => parseSiemUrl("tls://siem:99999")).toThrow();
  });
  it("logger redacts secrets", () => {
    const lines: string[] = [];
    const log = createLogger({ sink: (l) => lines.push(l) });
    log.info("x", { apiKey: "SECRET", nested: { privateKey: "PEM", ok: 1 }, code: "AAAA-BBBB" });
    expect(lines[0]).not.toContain("SECRET");
    expect(lines[0]).not.toContain("PEM");
    expect(lines[0]).not.toContain("AAAA-BBBB");
    expect(JSON.parse(lines[0]!).nested.ok).toBe(1);
  });
  it("parses CLI arguments strictly", () => {
    expect(parseArgs(["init", "--config", "c.json", "--server=https://pg", "--insecure-dev"])).toEqual({
      command: "init",
      flags: { config: "c.json", server: "https://pg", "insecure-dev": true },
    });
    expect(() => parseArgs(["run", "--bogus"])).toThrow();
    expect(() => parseArgs(["run", "--config"])).toThrow();
  });
  it("validates packages like the PC-side install script", () => {
    const msi: JobPackage = { kind: "msi", wingetId: "7zip.7zip", version: "24.08", sha256: "a".repeat(64), size: 10, repoPath: "pkgs/7zip/24.08/7z.msi", publisher: "O=Igor Pavlov", switches: "" };
    expect(() => assertDeployablePackage(msi)).not.toThrow();
    expect(() => assertDeployablePackage({ ...msi, switches: "/S" })).toThrow();
    expect(() => assertDeployablePackage({ ...msi, repoPath: "pkgs/7zip/24.08/7z.exe" })).toThrow();
    expect(() => assertDeployablePackage({ ...msi, publisher: "CN=evil" })).toThrow();
    expect(() => assertDeployablePackage({ ...msi, kind: "exe", repoPath: "pkgs/a/1/a.exe", switches: "/S /D=x" })).not.toThrow();
    expect(() => assertDeployablePackage({ ...msi, kind: "exe", repoPath: "pkgs/a/1/a.exe", switches: "/S & calc" })).toThrow();
    expect(() => assertDeployablePackage({ ...msi, kind: "agent", wingetId: "Tactical.Agent", version: "2.11.0", publisher: "", repoPath: "tactical/agent/2.11.0/tacticalagent-v2.11.0-windows-amd64.exe" })).not.toThrow();
    expect(parseInstallResult("log\nPATCHGATE_RESULT=OK\n")).toEqual({ ok: true });
    expect(parseInstallResult("PATCHGATE_RESULT=FAIL:hash mismatch")).toEqual({ ok: false, reason: "FAIL:hash mismatch" });
    expect(parseInstallResult("nothing")).toMatchObject({ ok: false });
    expect(isTransientInstallFailure("FAIL:The remote server returned an error: (503) Server Unavailable.")).toBe(true);
    expect(isTransientInstallFailure("FAIL:hash mismatch")).toBe(false);
    expect(compareVersions("2.11.0", "2.10.0")).toBeGreaterThan(0);
    expect(compareVersions("v2.10", "2.10.0")).toBe(0);
  });
});

describe("http client timeouts", () => {
  it("tears down a request whose server never answers", async () => {
    const { createServer } = await import("node:http");
    const { httpRequest, HttpNetworkError } = await import("../src/util/http.ts");
    let closed = false;
    const srv = createServer((req) => {
      req.socket.on("close", () => (closed = true)); // never respond
    });
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", () => r()));
    const port = (srv.address() as { port: number }).port;
    await expect(httpRequest({ method: "GET", url: new URL(`http://127.0.0.1:${port}/`), timeoutMs: 200 })).rejects.toBeInstanceOf(HttpNetworkError);
    await new Promise((r) => setTimeout(r, 100));
    expect(closed).toBe(true);
    srv.close();
  });
});
