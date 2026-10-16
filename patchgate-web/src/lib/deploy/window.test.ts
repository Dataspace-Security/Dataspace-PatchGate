import { describe, expect, it } from "vitest";
import { isWithinWindow } from "./window";

// Sunday 02:00–04:00 India time (UTC+5:30) => Saturday 20:30–22:30 UTC
const sunday2am = { cron: "0 2 * * 0", durationMin: 120, timezone: "Asia/Kolkata" };

describe("isWithinWindow", () => {
  it("is open inside the window", () => {
    expect(isWithinWindow(sunday2am, new Date("2026-10-17T21:00:00Z"))).toBe(true);
  });

  it("is open exactly at the start", () => {
    expect(isWithinWindow(sunday2am, new Date("2026-10-17T20:30:00Z"))).toBe(true);
  });

  it("is closed after the duration ends", () => {
    expect(isWithinWindow(sunday2am, new Date("2026-10-17T22:30:00Z"))).toBe(false);
  });

  it("is closed on other days", () => {
    expect(isWithinWindow(sunday2am, new Date("2026-10-14T21:00:00Z"))).toBe(false);
  });

  it("respects the endpoint timezone, not server time", () => {
    // 02:30 UTC Sunday is 08:00 IST — outside the 02:00 IST window
    expect(isWithinWindow(sunday2am, new Date("2026-10-18T02:30:00Z"))).toBe(false);
  });

  it("fails closed on an invalid cron expression", () => {
    expect(isWithinWindow({ ...sunday2am, cron: "not a cron" }, new Date())).toBe(false);
  });
});
