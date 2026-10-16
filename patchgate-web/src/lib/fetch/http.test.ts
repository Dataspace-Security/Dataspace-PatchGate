import { mkdtempSync, readFileSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import { assertAllowedUrl, assertPublicHttpsUrl, isNonPublic, safeDownload, safeFetchText } from "./http";

const HOSTS = ["dl.google.com", "raw.githubusercontent.com"];
/** Unit tests never touch real DNS. */
const L = async () => [{ address: "142.250.0.1" }];

describe("assertAllowedUrl", () => {
  it("accepts https on an allow-listed host", () => {
    expect(assertAllowedUrl("https://dl.google.com/x.msi", HOSTS).hostname).toBe("dl.google.com");
  });
  it.each([
    ["http scheme", "http://dl.google.com/x.msi"],
    ["host not listed", "https://evil.example/x.msi"],
    ["suffix trick", "https://dl.google.com.evil.example/x"],
    ["userinfo trick", "https://dl.google.com@evil.example/x"],
    ["non-default port", "https://dl.google.com:8443/x"],
    ["IP literal", "https://127.0.0.1/x"],
  ])("rejects %s", (_n, url) => {
    expect(() => assertAllowedUrl(url, HOSTS)).toThrow();
  });
});

describe("assertPublicHttpsUrl", () => {
  it("accepts any https hostname", () => {
    expect(assertPublicHttpsUrl("https://mirror.example.org/v.exe").hostname).toBe("mirror.example.org");
  });
  it.each([
    ["http scheme", "http://mirror.example.org/x"],
    ["IPv4 literal", "https://10.0.0.5/x"],
    ["IPv6 literal", "https://[::1]/x"],
    ["IPv6 literal (public)", "https://[2606:4700::1111]/x"],
    ["userinfo", "https://a@mirror.example.org/x"],
    ["non-default port", "https://mirror.example.org:444/x"],
  ])("rejects %s", (_n, url) => {
    expect(() => assertPublicHttpsUrl(url)).toThrow();
  });
});

function fakeFetch(routes: Record<string, () => Response>) {
  return vi.fn(async (input: string | URL | Request) => {
    const url = String(input);
    const r = routes[url];
    if (!r) throw new Error(`unexpected fetch ${url}`);
    return r();
  }) as unknown as typeof fetch;
}

describe("safeFetchText", () => {
  it("follows a redirect only to another allowed host", async () => {
    const f = fakeFetch({
      "https://raw.githubusercontent.com/a": () => new Response(null, { status: 302, headers: { location: "https://dl.google.com/b" } }),
      "https://dl.google.com/b": () => new Response("ok"),
    });
    expect(await safeFetchText("https://raw.githubusercontent.com/a", { allowedHosts: HOSTS, timeoutMs: 1000, fetchImpl: f, lookup: L })).toBe("ok");
  });

  it("refuses a redirect to a non-allowed host", async () => {
    const f = fakeFetch({
      "https://dl.google.com/a": () => new Response(null, { status: 302, headers: { location: "https://evil.example/b" } }),
    });
    await expect(safeFetchText("https://dl.google.com/a", { allowedHosts: HOSTS, timeoutMs: 1000, fetchImpl: f, lookup: L })).rejects.toThrow(/not allowed/);
  });

  it("stops redirect loops", async () => {
    const f = fakeFetch({
      "https://dl.google.com/a": () => new Response(null, { status: 302, headers: { location: "https://dl.google.com/a" } }),
    });
    await expect(safeFetchText("https://dl.google.com/a", { allowedHosts: HOSTS, timeoutMs: 1000, fetchImpl: f, lookup: L })).rejects.toThrow(/redirects/);
  });
});

describe("safeDownload", () => {
  let dir = "";
  afterEach(() => dir && rmSync(dir, { recursive: true, force: true }));

  it("streams to disk and returns sha256 + size", async () => {
    dir = mkdtempSync(join(tmpdir(), "pg-dl-"));
    const body = Buffer.from("installer-bytes");
    const f = fakeFetch({ "https://dl.google.com/x.msi": () => new Response(body) });
    const dest = join(dir, "x.msi");
    const r = await safeDownload("https://dl.google.com/x.msi", dest, { allowedHosts: HOSTS, timeoutMs: 1000, maxBytes: 1000, fetchImpl: f, lookup: L });
    expect(r).toEqual({ sha256: createHash("sha256").update(body).digest("hex"), size: body.length });
    expect(readFileSync(dest)).toEqual(body);
  });

  it("aborts and deletes the partial file when over the size limit", async () => {
    dir = mkdtempSync(join(tmpdir(), "pg-dl-"));
    const f = fakeFetch({ "https://dl.google.com/big": () => new Response(Buffer.alloc(5000)) });
    const dest = join(dir, "big");
    await expect(
      safeDownload("https://dl.google.com/big", dest, { allowedHosts: HOSTS, timeoutMs: 1000, maxBytes: 100, fetchImpl: f, lookup: L }),
    ).rejects.toThrow(/size limit/);
    expect(existsSync(dest)).toBe(false);
  });
});

describe("egress hardening", () => {
  const publicLookup = async () => [{ address: "142.250.0.1" }];

  it("refuses hosts that resolve to private / loopback addresses (SSRF into the bank)", async () => {
    for (const ip of ["10.1.2.3", "192.168.1.5", "172.16.0.9", "127.0.0.1", "169.254.169.254", "100.64.0.1", "::1", "fd00::1"]) {
      const f = vi.fn() as unknown as typeof fetch;
      await expect(
        safeFetchText("https://dl.google.com/x", { allowedHosts: HOSTS, timeoutMs: 1000, fetchImpl: f, lookup: async () => [{ address: ip }] }),
      ).rejects.toThrow(/non-public/);
      expect(f).not.toHaveBeenCalled();
    }
  });

  it("sends auth headers only to the configured host, never to redirect targets", async () => {
    const seen: Record<string, string | null> = {};
    const f = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
      const url = String(input);
      seen[new URL(url).hostname] = new Headers(init?.headers).get("authorization");
      return url.includes("raw.githubusercontent.com")
        ? new Response("ok")
        : new Response(null, { status: 302, headers: { location: "https://raw.githubusercontent.com/x" } });
    }) as unknown as typeof fetch;
    await safeFetchText("https://api.github.com/a", {
      allowedHosts: ["api.github.com", "raw.githubusercontent.com"],
      timeoutMs: 1000,
      fetchImpl: f,
      lookup: publicLookup,
      authHeaders: { host: "api.github.com", headers: { Authorization: "Bearer t" } },
    });
    expect(seen["api.github.com"]).toBe("Bearer t");
    expect(seen["raw.githubusercontent.com"]).toBeNull();
  });

  it("caps text responses while streaming (no unbounded buffering)", async () => {
    const f = vi.fn(async () => new Response("x".repeat(10_000))) as unknown as typeof fetch;
    await expect(
      safeFetchText("https://dl.google.com/x", { allowedHosts: HOSTS, timeoutMs: 1000, fetchImpl: f, lookup: publicLookup, maxTextBytes: 1000 }),
    ).rejects.toThrow(/too large/);
  });
});

describe("isNonPublic", () => {
  it.each([
    ["142.250.0.1", false],
    ["2607:f8b0:4004::1", false],
    ["10.0.0.1", true],
    ["::ffff:10.0.0.1", true],
    ["::ffff:142.250.0.1", false],
    ["fe80::1", true],
    ["garbage", true],
  ])("%s -> %s", (ip, expected) => {
    expect(isNonPublic(ip)).toBe(expected);
  });
});

describe("redirect policy: content-verified downloads (mirrors)", () => {
  const L2 = async () => [{ address: "142.250.0.1" }];
  it("allows redirects to any PUBLIC https host when redirects=public (hash+signature protect the bytes)", async () => {
    const f = fakeFetch({
      "https://get.videolan.org/vlc.msi": () => new Response(null, { status: 302, headers: { location: "https://mirror.random-isp.example/vlc.msi" } }),
      "https://mirror.random-isp.example/vlc.msi": () => new Response("ok"),
    });
    expect(
      await safeFetchText("https://get.videolan.org/vlc.msi", { allowedHosts: ["get.videolan.org"], redirects: "public", timeoutMs: 1000, fetchImpl: f, lookup: L2 }),
    ).toBe("ok");
  });

  it("still requires the FIRST hop to be allow-listed", async () => {
    const f = fakeFetch({});
    await expect(
      safeFetchText("https://evil.example/x", { allowedHosts: ["get.videolan.org"], redirects: "public", timeoutMs: 1000, fetchImpl: f, lookup: L2 }),
    ).rejects.toThrow(/not allowed/);
  });

  it("never follows a redirect to http, an IP literal, or a host resolving to a private address", async () => {
    for (const loc of ["http://mirror.example/x", "https://10.0.0.5/x"]) {
      const f = fakeFetch({ "https://get.videolan.org/x": () => new Response(null, { status: 302, headers: { location: loc } }) });
      await expect(
        safeFetchText("https://get.videolan.org/x", { allowedHosts: ["get.videolan.org"], redirects: "public", timeoutMs: 1000, fetchImpl: f, lookup: L2 }),
      ).rejects.toThrow();
    }
    const f = fakeFetch({
      "https://get.videolan.org/x": () => new Response(null, { status: 302, headers: { location: "https://internal-mirror.example/x" } }),
    });
    const lookup = async (h: string) => [{ address: h === "internal-mirror.example" ? "10.1.1.1" : "142.250.0.1" }];
    await expect(
      safeFetchText("https://get.videolan.org/x", { allowedHosts: ["get.videolan.org"], redirects: "public", timeoutMs: 1000, fetchImpl: f, lookup }),
    ).rejects.toThrow(/non-public/);
  });

  it("default (allowlist) policy still blocks unlisted redirect hosts", async () => {
    const f = fakeFetch({
      "https://get.videolan.org/x": () => new Response(null, { status: 302, headers: { location: "https://mirror.random-isp.example/x" } }),
    });
    await expect(
      safeFetchText("https://get.videolan.org/x", { allowedHosts: ["get.videolan.org"], timeoutMs: 1000, fetchImpl: f, lookup: L2 }),
    ).rejects.toThrow(/not allowed/);
  });
});
