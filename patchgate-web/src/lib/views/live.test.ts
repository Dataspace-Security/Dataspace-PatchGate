import { describe, expect, it } from "vitest";
import { LIVE_ACTIVE_MS, LIVE_IDLE_MS, liveIntervalMs, refreshDue, updatedAgoText } from "./live";

describe("live refresh", () => {
  it("5 s while work is active, 30 s when idle", () => {
    expect(liveIntervalMs(true)).toBe(LIVE_ACTIVE_MS);
    expect(liveIntervalMs(false)).toBe(LIVE_IDLE_MS);
    expect(LIVE_ACTIVE_MS).toBe(5_000);
    expect(LIVE_IDLE_MS).toBe(30_000);
  });

  it("refreshes when due, never while the tab is hidden", () => {
    expect(refreshDue(10_000, 5_000, true, false)).toBe(true);
    expect(refreshDue(9_000, 5_000, true, false)).toBe(false);
    expect(refreshDue(20_000, 5_000, false, false)).toBe(false);
    expect(refreshDue(35_000, 5_000, false, false)).toBe(true);
    expect(refreshDue(60_000, 0, true, true)).toBe(false);
  });

  it("indicator text, never negative", () => {
    expect(updatedAgoText(1_000, 1_000)).toBe("updated just now");
    expect(updatedAgoText(1_000, 5_000)).toBe("updated just now");
    expect(updatedAgoText(13_000, 1_000)).toBe("updated 12s ago");
    expect(updatedAgoText(181_000, 1_000)).toBe("updated 3 min ago");
  });
});
