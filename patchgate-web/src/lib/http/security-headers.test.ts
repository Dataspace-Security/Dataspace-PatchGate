import { describe, expect, it } from "vitest";
import { idpOriginOf, securityHeaders } from "./security-headers";

const directives = (csp: string) => Object.fromEntries(csp.split("; ").map((d) => [d.split(" ")[0], d.split(" ").slice(1).join(" ")]));

describe("securityHeaders", () => {
  it("production: strict CSP, HSTS, no eval, IdP only in form-action", () => {
    const h = securityHeaders({ isDev: false, idpOrigin: "https://sso.bank.local", https: true });
    const d = directives(h["Content-Security-Policy"]);
    expect(d["default-src"]).toBe("'self'");
    expect(d["script-src"]).toBe("'self' 'unsafe-inline'");
    expect(d["connect-src"]).toBe("'self'");
    expect(d["frame-ancestors"]).toBe("'none'");
    expect(d["object-src"]).toBe("'none'");
    expect(d["base-uri"]).toBe("'none'");
    expect(d["form-action"]).toBe("'self' https://sso.bank.local");
    expect(h["Content-Security-Policy"]).toContain("upgrade-insecure-requests");
    expect(h["Strict-Transport-Security"]).toMatch(/max-age=31536000/);
    expect(h["X-Frame-Options"]).toBe("DENY");
    expect(h["X-Content-Type-Options"]).toBe("nosniff");
    expect(h["Referrer-Policy"]).toBe("same-origin");
  });
  it("development: eval + websocket for HMR, no HSTS", () => {
    const h = securityHeaders({ isDev: true, idpOrigin: null, https: true });
    const d = directives(h["Content-Security-Policy"]);
    expect(d["script-src"]).toContain("'unsafe-eval'");
    expect(d["connect-src"]).toContain("ws:");
    expect(d["form-action"]).toBe("'self'");
    expect(h["Strict-Transport-Security"]).toBeUndefined();
  });
  it("no HSTS over plain http", () => {
    expect(securityHeaders({ isDev: false, idpOrigin: null, https: false })["Strict-Transport-Security"]).toBeUndefined();
  });
});

describe("idpOriginOf", () => {
  it.each([
    ["https://login.microsoftonline.com/tenant/v2.0", "https://login.microsoftonline.com"],
    ["https://localhost:8443/realms/bank", "https://localhost:8443"],
    ["http://sso.bank.local/realms/bank", null],
    ["not a url", null],
    [undefined, null],
  ])("%s → %s", (issuer, expected) => {
    expect(idpOriginOf(issuer)).toBe(expected);
  });
});
