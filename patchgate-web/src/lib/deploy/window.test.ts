import { describe, expect, it } from "vitest";
import { isWithinWindow, outsideWindowNote } from "./window";

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

describe("outsideWindowNote", () => {
  it("names the window and when it next opens (UTC), with the waiting prefix the progress view keeps in Queued", () => {
    const note = outsideWindowNote({ name: "Sun 02:00", cron: "0 2 * * 0", timezone: "UTC" }, new Date("2026-10-14T10:00:00Z"));
    expect(note).toBe('waiting for the maintenance window "Sun 02:00" (next opens 2026-10-18 02:00 UTC)');
  });

  it("converts the bank's timezone to UTC and says so when the schedule is invalid", () => {
    expect(outsideWindowNote({ name: "IST night", cron: "0 2 * * *", timezone: "Asia/Kolkata" }, new Date("2026-10-14T10:00:00Z"))).toContain(
      "next opens 2026-10-14 20:30 UTC",
    );
    expect(outsideWindowNote({ name: "Broken", cron: "not a cron", timezone: "UTC" }, new Date())).toMatch(/schedule is invalid/);
  });
});
