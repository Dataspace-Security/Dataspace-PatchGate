import { describe, expect, it } from "vitest";
import { DomainError } from "@/lib/errors";
import {
  TenantRequiredError,
  assertSameTenant,
  canActForTenant,
  isPlatformAdmin,
  isPlatformUser,
  isValidTenantId,
  requestedTenantId,
  type TenantUser,
} from "./policy";

const platformOperator: TenantUser = { role: "AUDITOR", tenantId: null }; // platform auditor (read-only staff)
const platformAdmin: TenantUser = { role: "ADMIN", tenantId: null };
const bankAdmin: TenantUser = { role: "ADMIN", tenantId: "bank-a" };

describe("tenant id validation", () => {
  it("accepts cuids and seeded ids", () => {
    expect(isValidTenantId("tenant-default")).toBe(true);
    expect(isValidTenantId("cm2x9q0k30000abcd1234efgh")).toBe(true);
  });
  it("rejects anything that is not a plain id", () => {
    for (const v of ["", " ", "a b", "x' OR '1'='1", "../etc", "-leading", "a".repeat(65), undefined, null, 42]) {
      expect(isValidTenantId(v)).toBe(false);
    }
  });
});

describe("requestedTenantId", () => {
  it("bank users always act for their own bank — the cookie is ignored", () => {
    expect(requestedTenantId(bankAdmin, "bank-b")).toBe("bank-a");
    expect(requestedTenantId(bankAdmin, undefined)).toBe("bank-a");
  });
  it("platform staff act for the bank in the cookie, if well-formed", () => {
    expect(requestedTenantId(platformOperator, "bank-b")).toBe("bank-b");
    expect(requestedTenantId(platformOperator, undefined)).toBeNull();
    expect(requestedTenantId(platformOperator, "bad id;")).toBeNull();
  });
});

describe("roles across banks", () => {
  it("knows platform staff and platform admins", () => {
    expect(isPlatformUser(platformOperator)).toBe(true);
    expect(isPlatformUser(bankAdmin)).toBe(false);
    expect(isPlatformAdmin(platformAdmin)).toBe(true);
    expect(isPlatformAdmin(platformOperator)).toBe(false);
    expect(isPlatformAdmin(bankAdmin)).toBe(false); // a bank admin is never a platform admin
  });
  it("bank users may only act for their own bank; platform staff for any", () => {
    expect(canActForTenant(bankAdmin, "bank-a")).toBe(true);
    expect(canActForTenant(bankAdmin, "bank-b")).toBe(false);
    expect(canActForTenant(platformOperator, "bank-b")).toBe(true);
  });
});

describe("assertSameTenant", () => {
  it("passes for the active bank's rows", () => {
    expect(() => assertSameTenant("bank-a", "bank-a")).not.toThrow();
  });
  it("reports another bank's (or an ownerless) row as not found (404), never as forbidden", () => {
    for (const row of ["bank-b", null, undefined]) {
      try {
        assertSameTenant("bank-a", row, "Endpoint");
        expect.unreachable();
      } catch (err: unknown) {
        expect(err).toBeInstanceOf(DomainError);
        expect(err).toMatchObject({ status: 404, message: "Endpoint not found" });
      }
    }
  });
});

describe("TenantRequiredError", () => {
  it("is a 409 DomainError with a user-facing hint", () => {
    const e = new TenantRequiredError();
    expect(e).toBeInstanceOf(DomainError);
    expect(e.status).toBe(409);
    expect(e.message).toMatch(/select a bank/i);
  });
});
