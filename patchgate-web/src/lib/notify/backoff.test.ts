import { describe, expect, it } from "vitest";
import { MAX_ATTEMPTS, afterFailure, backoffMs } from "./backoff";
import { classifySmtpError } from "./smtp";

describe("backoff", () => {
  it("doubles from 1 minute and caps at 6 hours", () => {
    expect(backoffMs(1)).toBe(60_000);
    expect(backoffMs(2)).toBe(120_000);
    expect(backoffMs(5)).toBe(16 * 60_000);
    expect(backoffMs(50)).toBe(6 * 3_600_000);
    expect(backoffMs(0)).toBe(60_000);
  });

  it("dead-letters permanent errors and exhausted attempts", () => {
    const now = new Date(0);
    expect(afterFailure(1, false, now)).toEqual({ status: "PENDING", nextAttemptAt: new Date(60_000) });
    expect(afterFailure(1, true, now)).toEqual({ status: "DEAD" });
    expect(afterFailure(MAX_ATTEMPTS, false, now)).toEqual({ status: "DEAD" });
  });
});

describe("SMTP error classification", () => {
  it("5xx is permanent, 4xx / network is retried, the SMTP URL is never echoed", () => {
    expect(classifySmtpError({ responseCode: 550, message: "550 mailbox unavailable" })).toMatchObject({ permanent: true });
    expect(classifySmtpError({ responseCode: 451, message: "try later" })).toMatchObject({ permanent: false });
    expect(classifySmtpError({ code: "ECONNREFUSED", message: "connect smtps://user:pw@mail:465 refused" })).toEqual({ permanent: false, error: "SMTP ECONNREFUSED: connect [smtp-url] refused" });
    expect(classifySmtpError("weird")).toEqual({ permanent: false, error: "SMTP error" });
  });
});
