import { NextRequest } from "next/server";
import { describe, expect, it } from "vitest";
import { proxy } from "./proxy";

// NODE_ENV=test without AUTH_MODE → local login is required for pages (the production default).
const get = (path: string) => proxy(new NextRequest(new URL(path, "https://patchgate.test.local")));

describe("proxy: one-line site install is machine traffic", () => {
  it("never redirects /install/* to /login, but keeps the security headers and rate-limit headers", () => {
    for (const p of ["/install/site.sh", "/install/bundle/latest/SHA256SUMS", "/install/bundle/1.0/patchgate-site-1.0.tar.gz"]) {
      const res = get(p);
      expect(res.status).toBe(200);
      expect(res.headers.get("location")).toBeNull();
      expect(res.headers.get("x-content-type-options")).toBe("nosniff");
      expect(res.headers.get("content-security-policy")).toBeTruthy();
      expect(res.headers.get("ratelimit-limit")).toBe("3");
    }
  });

  it("pages without a session still go to sign-in", () => {
    const res = get("/connectors");
    expect(res.status).toBe(307);
    expect(res.headers.get("location")).toContain("/login");
    expect(get("/installer").headers.get("location")).toContain("/login");
  });
});
