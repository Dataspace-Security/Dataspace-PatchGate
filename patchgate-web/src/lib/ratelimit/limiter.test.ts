import { describe, expect, it } from "vitest";
import { classifyRequest, clientIp, connectorHeadersWellFormed, createClassLimiters, createFailureCounter, createLimiter, normalizeIp, normalizePath } from "./limiter";

describe("token bucket", () => {
  it("allows up to capacity, then blocks with a retry-after", () => {
    const t = 0;
    const l = createLimiter({ now: () => t });
    for (let i = 0; i < 5; i++) expect(l.take("k", { capacity: 5, perMinute: 5 }).ok).toBe(true);
    const blocked = l.take("k", { capacity: 5, perMinute: 5 });
    expect(blocked.ok).toBe(false);
    expect(blocked.retryAfterSec).toBe(12); // 1 token per 12s at 5/min
  });

  it("refills over time", () => {
    let t = 0;
    const l = createLimiter({ now: () => t });
    for (let i = 0; i < 5; i++) l.take("k", { capacity: 5, perMinute: 5 });
    t = 12_000;
    expect(l.take("k", { capacity: 5, perMinute: 5 }).ok).toBe(true);
    expect(l.take("k", { capacity: 5, perMinute: 5 }).ok).toBe(false);
  });

  it("keys are independent", () => {
    const l = createLimiter({ now: () => 0 });
    l.take("a", { capacity: 1, perMinute: 1 });
    expect(l.take("a", { capacity: 1, perMinute: 1 }).ok).toBe(false);
    expect(l.take("b", { capacity: 1, perMinute: 1 }).ok).toBe(true);
  });

  it("bounds memory by evicting the oldest keys", () => {
    const l = createLimiter({ now: () => 0, maxKeys: 3 });
    for (const k of ["a", "b", "c", "d"]) l.take(k, { capacity: 1, perMinute: 1 });
    expect(l.size()).toBe(3);
    expect(l.take("a", { capacity: 1, perMinute: 1 }).ok).toBe(true); // "a" was evicted → fresh bucket
  });
});

describe("class isolation", () => {
  it("flooding one class cannot evict the buckets of another class", () => {
    const l = createClassLimiters({ now: () => 0, maxKeysPerClass: 3 });
    l.take("auth", "victim", { capacity: 1, perMinute: 1 });
    for (let i = 0; i < 100; i++) l.take("page", `flood${i}`, { capacity: 1, perMinute: 1 });
    expect(l.take("auth", "victim", { capacity: 1, perMinute: 1 }).ok).toBe(false); // still limited
    expect(l.size("page")).toBe(3);
  });
});

describe("classifyRequest", () => {
  it.each([
    ["POST", "/api/dev-login", "auth", 20],
    ["POST", "/api/dev%2Dlogin", "auth", 20],
    ["POST", "/api//dev-login/", "auth", 20],
    ["GET", "/api/auth/login", "auth", 20],
    ["GET", "/api/auth/callback", "auth", 20],
    ["POST", "/api/%61uth/logout", "auth", 20],
    ["POST", "/api/account/password", "auth", 20],
    ["POST", "/api/%61ccount/password/", "auth", 20],
    ["POST", "/api//Account/sessions/revoke-others", "auth", 20],
    ["POST", "/api/accounts", "write", 60],
    ["POST", "/api/worker/tick", "machine-unauth", 10],
    ["POST", "/api/%77orker/tick", "machine-unauth", 10],
    ["GET", "/api/wsus/approvals", "machine-unauth", 10],
    ["POST", "/api/audit/verify", "audit", 20],
    ["GET", "/api/audit", "audit", 20],
    ["POST", "/api/change-requests", "write", 60],
    ["PATCH", "/api/endpoints/abc", "write", 60],
    ["GET", "/api/patches", "read", 300],
    ["GET", "/repo/pkgs/a/1/a.msi", "repo", 1200],
    ["GET", "/change-requests", "page", 600],
    ["GET", "/install/site.sh", "install", 3],
    ["GET", "/install/bundle/latest/SHA256SUMS", "install", 3],
    ["GET", "/%69nstall//bundle/1.0/x.tar.gz", "install", 3],
    ["GET", "/installer", "page", 600],
  ])("%s %s → %s (%i/min)", (method, path, name, perMinute) => {
    expect(classifyRequest(method, path)).toMatchObject({ name, perMinute });
  });

  it("a VALID machine token gets its own generous bucket; invalid/missing tokens get a tiny one", () => {
    expect(classifyRequest("POST", "/api/worker/tick", true)).toMatchObject({ name: "machine", perMinute: 120 });
    expect(classifyRequest("POST", "/api/worker/tick", false)).toMatchObject({ name: "machine-unauth", perMinute: 10 });
  });
});

describe("connector API classes", () => {
  it("signed-looking requests get the generous connector bucket; junk and enrolment stay tiny", () => {
    expect(classifyRequest("GET", "/api/connector/v1/jobs", false, true)).toMatchObject({ name: "connector", perMinute: 600 });
    expect(classifyRequest("GET", "/api/connector/v1/jobs", false, false)).toMatchObject({ name: "connector-unauth", perMinute: 20 });
    expect(classifyRequest("POST", "/api/connector/v1/enroll", false, true)).toMatchObject({ name: "connector-enroll", perMinute: 10 });
    expect(classifyRequest("POST", "/api/connector//v1/%6Aobs/", false, false)).toMatchObject({ name: "connector-unauth" });
    // the browser admin API is a normal session route
    expect(classifyRequest("POST", "/api/connector/admin/enrollments")).toMatchObject({ name: "write" });
  });

  it("pre-checks header shape and timestamp freshness without any secret", () => {
    const now = Date.UTC(2026, 9, 15, 12);
    const h = (over: Record<string, string> = {}) =>
      new Headers({
        "x-pg-connector": "cm2conn0001",
        "x-pg-timestamp": String(now),
        "x-pg-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
        "x-pg-signature": `${"A".repeat(86)}==`,
        ...over,
      });
    expect(connectorHeadersWellFormed(h(), now)).toBe("cm2conn0001");
    expect(connectorHeadersWellFormed(h({ "x-pg-timestamp": String(now - 6 * 60_000) }), now)).toBeNull();
    expect(connectorHeadersWellFormed(h({ "x-pg-connector": "bad id" }), now)).toBeNull();
    expect(connectorHeadersWellFormed(h({ "x-pg-nonce": "short" }), now)).toBeNull();
    expect(connectorHeadersWellFormed(h({ "x-pg-signature": "nope" }), now)).toBeNull();
  });
});

describe("normalizePath", () => {
  it("decodes, collapses slashes, drops trailing slash, lowercases", () => {
    expect(normalizePath("/API//Dev%2DLogin/")).toBe("/api/dev-login");
  });
  it("leaves malformed escapes as-is without throwing", () => {
    expect(normalizePath("/%E0%A4%A")).toBe("/%e0%a4%a");
  });
});

describe("normalizeIp", () => {
  it.each([
    ["1.2.3.4", "1.2.3.4"],
    ["1.2.3.4:5678", "1.2.3.4"],
    ["::ffff:1.2.3.4", "1.2.3.4"],
    ["2001:db8:1:2:aaaa:bbbb:cccc:dddd", "2001:0db8:0001:0002::/64"],
    ["2001:db8:1:2::99", "2001:0db8:0001:0002::/64"],
    ["[2001:db8:1:2::1]:443", "2001:0db8:0001:0002::/64"],
    ["fe80::1%eth0", "fe80:0000:0000:0000::/64"],
    ["garbage", null],
  ])("%s -> %s", (raw, expected) => {
    expect(normalizeIp(raw)).toBe(expected);
  });
});

describe("clientIp", () => {
  const h = (o: Record<string, string>) => new Headers(o);
  it("ignores forwarded headers unless a trusted proxy is configured (anti-spoofing)", () => {
    expect(clientIp(h({ "x-forwarded-for": "1.2.3.4" }), 0)).toBe("direct");
  });
  it("takes the client address added by the trusted proxy (right-most hops)", () => {
    expect(clientIp(h({ "x-forwarded-for": "6.6.6.6, 10.0.0.5" }), 1)).toBe("10.0.0.5");
    expect(clientIp(h({ "x-forwarded-for": "6.6.6.6, 10.0.0.5, 10.0.0.1" }), 2)).toBe("10.0.0.5");
  });
  it("handles ports and malformed headers", () => {
    expect(clientIp(h({ "x-forwarded-for": "10.0.0.5:51234" }), 1)).toBe("10.0.0.5");
    expect(clientIp(h({ "x-forwarded-for": "not-an-ip" }), 1)).toBe("direct");
    expect(clientIp(h({}), 1)).toBe("direct");
  });
  it("all addresses in one IPv6 /64 share a key (no key minting)", () => {
    expect(clientIp(h({ "x-forwarded-for": "2001:db8:1:2::1" }), 1)).toBe(clientIp(h({ "x-forwarded-for": "2001:db8:1:2:ffff::7" }), 1));
  });
});

describe("install class + failure counter", () => {
  it("the install class allows a burst of 30 per address (one site install = a handful of requests)", () => {
    const p = classifyRequest("GET", "/install/bundle/latest/SHA256SUMS");
    expect(p).toMatchObject({ name: "install", capacity: 30 });
    const l = createLimiter({ now: () => 0 });
    for (let i = 0; i < 30; i++) expect(l.take("ip", p).ok).toBe(true);
    expect(l.take("ip", p).ok).toBe(false);
  });

  it("blocks a key after maxFailures inside the window, and only that key", () => {
    let t = 0;
    const c = createFailureCounter({ maxFailures: 3, windowMs: 60_000, blockMs: 600_000, now: () => t });
    expect(c.fail("a")).toBe(0);
    expect(c.fail("a")).toBe(0);
    expect(c.blockedFor("a")).toBe(0);
    expect(c.fail("a")).toBe(600);
    expect(c.blockedFor("a")).toBe(600);
    expect(c.blockedFor("b")).toBe(0);
    t = 599_000;
    expect(c.fail("a")).toBeGreaterThan(0); // still blocked even after the counting window elapsed
    t = 601_000;
    expect(c.blockedFor("a")).toBe(0);
  });

  it("failures outside the window start a fresh count; memory is bounded", () => {
    let t = 0;
    const c = createFailureCounter({ maxFailures: 2, windowMs: 1000, blockMs: 5000, now: () => t, maxKeys: 2 });
    c.fail("a");
    t = 2000;
    expect(c.fail("a")).toBe(0);
    c.fail("b");
    c.fail("c");
    expect(c.size()).toBe(2);
  });
});
