import { describe, expect, it } from "vitest";
import { checkCron, formatInTimezone, isValidTimezone, nextOccurrences, windowInputSchema } from "./cron-preview";
import { approvalExpiryFrom, bankPolicySchema, requiredApprovalsFor, resolveRebootPolicy } from "./approval-policy";
import { DEFAULT_SECURITY_POLICY, inactiveToDisable, passwordExpired, securityPolicySchema, sessionsOverCap, type ActivityRow } from "./account-policy";
import { globToRegExp } from "./glob";

const DAY = 86_400_000;

describe("cron preview", () => {
  it("accepts 5-field cron with a real timezone, rejects the rest", () => {
    expect(checkCron("0 2 * * 0", "Asia/Kolkata")).toEqual({ ok: true });
    expect(checkCron("0 0 2 * * 0", "Asia/Kolkata").ok).toBe(false); // seconds field
    expect(checkCron("@daily", "UTC").ok).toBe(false);
    expect(checkCron("61 2 * * *", "UTC").ok).toBe(false);
    expect(checkCron("0 2 * * 0", "Mars/Olympus").ok).toBe(false);
    expect(isValidTimezone("Europe/London")).toBe(true);
    expect(isValidTimezone("")).toBe(false);
  });

  it("lists the next 5 occurrences in the window's timezone", () => {
    // Sunday 02:00 IST = Saturday 20:30 UTC
    const occ = nextOccurrences({ cron: "0 2 * * 0", durationMin: 120, timezone: "Asia/Kolkata" }, new Date("2026-10-16T00:00:00Z"));
    expect(occ).toHaveLength(5);
    expect(occ[0]!.start.toISOString()).toBe("2026-10-17T20:30:00.000Z");
    expect(occ[0]!.end.toISOString()).toBe("2026-10-17T22:30:00.000Z");
    expect(occ[1]!.start.getTime() - occ[0]!.start.getTime()).toBe(7 * DAY);
  });

  it("formats in the bank's timezone", () => {
    const s = formatInTimezone(new Date("2026-10-17T20:30:00Z"), "Asia/Kolkata");
    expect(s).toMatch(/Sun/);
    expect(s).toMatch(/02:00/);
    expect(nextOccurrences({ cron: "nope", durationMin: 60, timezone: "UTC" }, new Date())).toEqual([]);
  });

  it("window schema validates cron, duration and overlap", () => {
    const base = { name: "Sunday", ringId: "r1", cron: "0 2 * * 0", durationMin: 120, timezone: "Asia/Kolkata" };
    expect(windowInputSchema.safeParse(base).success).toBe(true);
    expect(windowInputSchema.safeParse({ ...base, cron: "0 * * * *", durationMin: 120 }).success).toBe(false); // hourly + 2 h overlaps
    expect(windowInputSchema.safeParse({ ...base, durationMin: 5 }).success).toBe(false);
    expect(windowInputSchema.safeParse({ ...base, cron: "bad cron x y" }).success).toBe(false);
  });
});

describe("approval policy", () => {
  it("two approvers for emergencies and requests above the target limit", () => {
    expect(requiredApprovalsFor({ emergency: true, targetCount: 1, maxTargetsPerCr: 0 })).toBe(2);
    expect(requiredApprovalsFor({ emergency: false, targetCount: 500, maxTargetsPerCr: 0 })).toBe(1);
    expect(requiredApprovalsFor({ emergency: false, targetCount: 101, maxTargetsPerCr: 100 })).toBe(2);
    expect(requiredApprovalsFor({ emergency: false, targetCount: 100, maxTargetsPerCr: 100 })).toBe(1);
  });

  it("approval expiry", () => {
    const at = new Date("2026-10-16T00:00:00Z");
    expect(approvalExpiryFrom(at, 0)).toBeNull();
    expect(approvalExpiryFrom(at, 7)!.toISOString()).toBe("2026-10-23T00:00:00.000Z");
  });

  it("reboot policy: explicit → ring override → bank default", () => {
    expect(resolveRebootPolicy(undefined, null, "REQUIRED")).toBe("REQUIRED");
    expect(resolveRebootPolicy(undefined, "NEVER", "REQUIRED")).toBe("NEVER");
    expect(resolveRebootPolicy("ALWAYS", "NEVER", "REQUIRED")).toBe("ALWAYS");
  });

  it("bank policy schema", () => {
    expect(bankPolicySchema.safeParse({ approvalExpiryDays: 14 }).success).toBe(true);
    expect(bankPolicySchema.safeParse({}).success).toBe(false);
    expect(bankPolicySchema.safeParse({ approvalExpiryDays: 400 }).success).toBe(false);
    expect(bankPolicySchema.safeParse({ timezone: "Nowhere/City" }).success).toBe(false);
  });
});

describe("account policy", () => {
  const now = new Date("2026-10-16T00:00:00Z");
  it("password max age", () => {
    const u = { passwordHash: "scrypt$x", passwordChangedAt: new Date(now.getTime() - 91 * DAY), createdAt: new Date(now.getTime() - 400 * DAY) };
    expect(passwordExpired(u, { passwordMaxAgeDays: 0 }, now)).toBe(false);
    expect(passwordExpired(u, { passwordMaxAgeDays: 90 }, now)).toBe(true);
    expect(passwordExpired(u, { passwordMaxAgeDays: 120 }, now)).toBe(false);
    expect(passwordExpired({ ...u, passwordChangedAt: null }, { passwordMaxAgeDays: 120 }, now)).toBe(true); // falls back to createdAt
    expect(passwordExpired({ ...u, passwordHash: null }, { passwordMaxAgeDays: 1 }, now)).toBe(false); // SSO-only user
  });

  it("session cap keeps the newest", () => {
    const s = (id: string, ageMin: number) => ({ id, createdAt: new Date(now.getTime() - ageMin * 60_000) });
    const list = [s("a", 30), s("b", 10), s("c", 20)];
    expect(sessionsOverCap(list, 2).map((x) => x.id)).toEqual(["a"]);
    expect(sessionsOverCap(list, 0).map((x) => x.id).sort()).toEqual(["a", "b", "c"]);
    expect(sessionsOverCap(list, 5)).toEqual([]);
  });

  it("inactivity keeps at least one platform admin", () => {
    const old = new Date(now.getTime() - 200 * DAY);
    const older = new Date(now.getTime() - 300 * DAY);
    const rows: ActivityRow[] = [
      { id: "bank-user", role: "ADMIN", tenantId: "t1", lastActivityAt: old },
      { id: "pa1", role: "ADMIN", tenantId: null, lastActivityAt: old },
      { id: "pa2", role: "ADMIN", tenantId: null, lastActivityAt: older },
      { id: "fresh", role: "AUDITOR", tenantId: "t1", lastActivityAt: new Date(now.getTime() - DAY) },
    ];
    // both platform admins stale and they are the only ones: the most recently active (pa1) stays
    expect(inactiveToDisable(rows, { inactivityDisableDays: 90 }, now, 2).map((r) => r.id)).toEqual(["bank-user", "pa2"]);
    // another active platform admin exists: both stale ones go
    expect(inactiveToDisable(rows, { inactivityDisableDays: 90 }, now, 3).map((r) => r.id)).toEqual(["bank-user", "pa1", "pa2"]);
    expect(inactiveToDisable(rows, { inactivityDisableDays: 0 }, now, 2)).toEqual([]);
  });

  it("schema", () => {
    expect(DEFAULT_SECURITY_POLICY.inactivityDisableDays).toBe(90);
    expect(securityPolicySchema.safeParse({ inactivityDisableDays: 3 }).success).toBe(false);
    expect(securityPolicySchema.safeParse({ inactivityDisableDays: 0, maxSessionsPerUser: 3 }).success).toBe(true);
    expect(securityPolicySchema.safeParse({}).success).toBe(false);
  });
});

describe("hostname glob", () => {
  it("matches * and ? case-insensitively and escapes the rest", () => {
    expect(globToRegExp("BR-PUNE-*").test("br-pune-0042")).toBe(true);
    expect(globToRegExp("BR-PUNE-*").test("BR-MUMBAI-1")).toBe(false);
    expect(globToRegExp("PC-??").test("PC-12")).toBe(true);
    expect(globToRegExp("PC-??").test("PC-123")).toBe(false);
    expect(globToRegExp("a.b").test("axb")).toBe(false);
  });
});
