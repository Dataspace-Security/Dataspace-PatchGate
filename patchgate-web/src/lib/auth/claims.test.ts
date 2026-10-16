import { describe, expect, it } from "vitest";
import { claimAt, parseRoleMap, roleFromClaims, safeReturnTo, sessionIsLive, shouldTouch, stringClaim } from "./claims";

const MAP = parseRoleMap("PatchGate.Auditor=AUDITOR; PatchGate.ReadOnly=auditor; PatchGate.Admin=admin");

describe("parseRoleMap", () => {
  it("parses entries (case-insensitive roles, ; or newline separated, = inside keys)", () => {
    expect(MAP.get("PatchGate.Admin")).toBe("ADMIN");
    expect(parseRoleMap("CN=PG-Admins,OU=Groups=ADMIN\nabc=AUDITOR").get("CN=PG-Admins,OU=Groups")).toBe("ADMIN");
    expect(MAP.get("PatchGate.ReadOnly")).toBe("AUDITOR");
  });
  it.each(["", "  ;  ", "PatchGate.Admin=ROOT", "=ADMIN", "NoEquals"])("rejects %j", (spec) => {
    expect(() => parseRoleMap(spec)).toThrow();
  });
  it.each(["G=VIEWER", "G=OPERATOR", "G=APPROVER", "PatchGate.Admin=ADMIN; G=APPROVER"])("rejects the retired role in %j (both user scopes)", (spec) => {
    expect(() => parseRoleMap(spec)).toThrow(/roles: ADMIN, AUDITOR/);
  });
});

describe("roleFromClaims", () => {
  it("picks the highest mapped role", () => {
    expect(roleFromClaims({ roles: ["PatchGate.Auditor", "PatchGate.Admin"] }, "roles", MAP)).toBe("ADMIN");
    expect(roleFromClaims({ roles: ["Other", "PatchGate.Auditor"] }, "roles", MAP)).toBe("AUDITOR");
  });
  it("reads nested claims (Keycloak realm roles) and single strings", () => {
    expect(roleFromClaims({ realm_access: { roles: ["PatchGate.Admin"] } }, "realm_access.roles", MAP)).toBe("ADMIN");
    expect(roleFromClaims({ role: "PatchGate.Auditor" }, "role", MAP)).toBe("AUDITOR");
  });
  it("returns null when nothing maps (no access)", () => {
    expect(roleFromClaims({ roles: ["Finance.Users"] }, "roles", MAP)).toBeNull();
    expect(roleFromClaims({}, "roles", MAP)).toBeNull();
    expect(roleFromClaims({ roles: [42, null] }, "roles", MAP)).toBeNull();
    expect(roleFromClaims({ roles: "patchgate.admin" }, "roles", MAP)).toBeNull(); // exact match only
  });
});

describe("claims", () => {
  it("claimAt walks dotted paths safely", () => {
    expect(claimAt({ a: { b: { c: 1 } } }, "a.b.c")).toBe(1);
    expect(claimAt({ a: "x" }, "a.b")).toBeUndefined();
    expect(claimAt({ a: null }, "a.b")).toBeUndefined();
  });
  it("stringClaim returns the first non-empty string", () => {
    expect(stringClaim({ upn: "", preferred_username: " u@bank " }, "upn", "preferred_username")).toBe("u@bank");
    expect(stringClaim({ upn: 5 }, "upn")).toBeNull();
  });
});

describe("safeReturnTo", () => {
  it.each([
    ["/change-requests/abc?x=1", "/change-requests/abc?x=1"],
    ["/", "/"],
    [null, "/"],
    ["https://evil.example/", "/"],
    ["//evil.example/", "/"],
    ["/\\evil.example", "/"],
    ["javascript:alert(1)", "/"],
    ["/api/auth/logout", "/"],
    ["/login?x", "/"],
    ["/ok\r\nSet-Cookie: x", "/"],
    [`/${"a".repeat(600)}`, "/"],
  ])("%j → %j", (input, expected) => {
    expect(safeReturnTo(input)).toBe(expected);
  });
});

describe("session lifetime", () => {
  const now = new Date("2026-10-15T10:00:00Z");
  const min = (m: number) => new Date(now.getTime() + m * 60_000);
  it("is live inside the idle window and before the absolute cap", () => {
    expect(sessionIsLive({ lastSeenAt: min(-14), expiresAt: min(60) }, now, 15)).toBe(true);
  });
  it("expires when idle too long", () => {
    expect(sessionIsLive({ lastSeenAt: min(-15), expiresAt: min(60) }, now, 15)).toBe(false);
  });
  it("expires at the absolute cap even if active", () => {
    expect(sessionIsLive({ lastSeenAt: now, expiresAt: now }, now, 15)).toBe(false);
  });
  it("throttles last-seen writes to once a minute", () => {
    expect(shouldTouch(min(-0.5), now)).toBe(false);
    expect(shouldTouch(min(-1), now)).toBe(true);
  });
});
