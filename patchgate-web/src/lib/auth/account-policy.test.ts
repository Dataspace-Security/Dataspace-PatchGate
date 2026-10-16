import { describe, expect, it } from "vitest";
import { changeOwnPasswordSchema, checkNewPassword, CONFIRM_MISMATCH, SAME_PASSWORD } from "./account-policy";

const UPN = "alice@bank-a.test";
const STRONG = "orbit-Kettle-7-sandstone-river";
const NEXT = "harbour-Lantern-4-meadow-quartz";

describe("self-service password change rules", () => {
  it("accepts a strong, confirmed, different password", () => {
    expect(checkNewPassword({ currentPassword: STRONG, newPassword: NEXT, confirmPassword: NEXT }, UPN)).toEqual({ ok: true });
  });

  it("rejects a confirmation mismatch before anything else", () => {
    expect(checkNewPassword({ currentPassword: STRONG, newPassword: NEXT, confirmPassword: `${NEXT}x` }, UPN)).toEqual({ ok: false, reason: CONFIRM_MISMATCH });
  });

  it("rejects reusing the current password", () => {
    expect(checkNewPassword({ currentPassword: STRONG, newPassword: STRONG, confirmPassword: STRONG }, UPN)).toEqual({ ok: false, reason: SAME_PASSWORD });
  });

  it("enforces the password policy (length, username, common passwords)", () => {
    const r = (p: string) => checkNewPassword({ currentPassword: STRONG, newPassword: p, confirmPassword: p }, UPN);
    expect(r("short-1A")).toMatchObject({ ok: false, reason: expect.stringMatching(/at least 14/) });
    expect(r("alice-is-my-name-2026")).toMatchObject({ ok: false, reason: expect.stringMatching(/username/) });
    expect(r("Password12345678")).toMatchObject({ ok: false, reason: expect.stringMatching(/common/) });
  });

  it("schema requires all three fields and caps their size", () => {
    expect(changeOwnPasswordSchema.safeParse({ currentPassword: "", newPassword: NEXT, confirmPassword: NEXT }).success).toBe(false);
    expect(changeOwnPasswordSchema.safeParse({ currentPassword: STRONG, newPassword: NEXT }).success).toBe(false);
    expect(changeOwnPasswordSchema.safeParse({ currentPassword: "x".repeat(1025), newPassword: NEXT, confirmPassword: NEXT }).success).toBe(false);
    expect(changeOwnPasswordSchema.safeParse({ currentPassword: STRONG, newPassword: NEXT, confirmPassword: NEXT }).success).toBe(true);
  });
});
