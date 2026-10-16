import { describe, expect, it } from "vitest";
import {
  ACTIVE_ROLES,
  ROLE_LABEL,
  canCheck,
  canMake,
  canRead,
  canWrite,
  isActiveRole,
  isAuditor,
  isPlatformReader,
  roleDescription,
  roleOptions,
  rolesFor,
  scopeOf,
  type Role,
} from "./roles";

const platformAdmin = { role: "ADMIN" as Role, tenantId: null };
const platformAuditor = { role: "AUDITOR" as Role, tenantId: null };
const bankAdmin = { role: "ADMIN" as Role, tenantId: "bank-a" };
const bankAuditor = { role: "AUDITOR" as Role, tenantId: "bank-a" };
const retired: Role[] = ["VIEWER", "OPERATOR", "APPROVER"];

describe("role model: ADMIN and AUDITOR, the same in every scope", () => {
  it("grants exactly the two active roles in both scopes", () => {
    expect([...ACTIVE_ROLES]).toEqual(["ADMIN", "AUDITOR"]);
    expect(rolesFor("platform")).toEqual(["ADMIN", "AUDITOR"]);
    expect(rolesFor("bank")).toEqual(["ADMIN", "AUDITOR"]);
    for (const r of retired) expect(isActiveRole(r)).toBe(false);
    expect(isActiveRole("ROOT")).toBe(false);
  });

  it("admins write, make and read; auditors only read; retired roles nothing", () => {
    for (const u of [platformAdmin, bankAdmin]) {
      expect([canWrite(u), canMake(u), canRead(u)]).toEqual([true, true, true]);
    }
    for (const u of [platformAuditor, bankAuditor]) {
      expect([canWrite(u), canMake(u), canRead(u), isAuditor(u)]).toEqual([false, false, true, true]);
    }
    for (const role of retired) {
      const u = { role, tenantId: "bank-a" };
      expect([canWrite(u), canMake(u), canRead(u)]).toEqual([false, false, false]);
    }
  });

  it("only an admin OF THE BANK is that bank's checker", () => {
    expect(canCheck(bankAdmin, "bank-a")).toBe(true);
    expect(canCheck(bankAdmin, "bank-b")).toBe(false);
    expect(canCheck(platformAdmin, "bank-a")).toBe(false);
    expect(canCheck(bankAuditor, "bank-a")).toBe(false);
  });

  it("platform readers = platform admins and auditors", () => {
    expect(isPlatformReader(platformAdmin)).toBe(true);
    expect(isPlatformReader(platformAuditor)).toBe(true);
    expect(isPlatformReader(bankAdmin)).toBe(false);
    expect(isPlatformReader({ role: "OPERATOR", tenantId: null })).toBe(false);
    expect(scopeOf(platformAuditor)).toBe("platform");
    expect(scopeOf(bankAuditor)).toBe("bank");
  });

  it("labels and one-line descriptions per scope", () => {
    expect(ROLE_LABEL.ADMIN).toBe("Admin");
    expect(ROLE_LABEL.AUDITOR).toBe("Auditor (read-only)");
    expect(roleDescription("ADMIN", "bank")).toMatch(/approves/);
    expect(roleDescription("AUDITOR", "platform")).toMatch(/every bank/);
    expect(roleDescription("APPROVER", "bank")).toMatch(/retired/i);
    expect(roleOptions("bank").map((o) => o.value)).toEqual(["ADMIN", "AUDITOR"]);
    expect(roleOptions("platform").every((o) => o.description.length > 10)).toBe(true);
  });
});
