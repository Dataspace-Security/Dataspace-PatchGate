import { describe, expect, it } from "vitest";
import {
  MAX_STAGGER_MS,
  OFFLINE_AFTER_MS,
  STAGGER_PER_SLOT_MS,
  installSlots,
  isInstallJob,
  isOnline,
  retryDelayMs,
  ringShouldStop,
  staggerOffsetMs,
} from "./policy";

describe("connector online state", () => {
  const now = new Date("2026-10-15T12:00:00Z");
  it("is online within 10 minutes of the last request", () => {
    expect(isOnline(new Date(now.getTime() - OFFLINE_AFTER_MS), now)).toBe(true);
    expect(isOnline(new Date(now.getTime() - OFFLINE_AFTER_MS - 1), now)).toBe(false);
  });
  it("never seen = offline", () => {
    expect(isOnline(null, now)).toBe(false);
  });
});

describe("LAN protection", () => {
  it("only DEPLOY_* and WU_INSTALL count as installs", () => {
    expect(isInstallJob("DEPLOY_PACKAGE")).toBe(true);
    expect(isInstallJob("DEPLOY_WINDOWS")).toBe(true);
    expect(isInstallJob("WU_INSTALL")).toBe(true);
    expect(isInstallJob("CACHE_PACKAGE")).toBe(false);
    expect(isInstallJob("COLLECT")).toBe(false);
  });

  it("free install slots never go negative", () => {
    expect(installSlots(50, 10)).toBe(40);
    expect(installSlots(3, 3)).toBe(0);
    expect(installSlots(3, 7)).toBe(0);
  });

  it("stagger grows with the wave size, inside a quarter of the remaining window and under the cap", () => {
    expect(staggerOffsetMs(60 * 60_000, 500, () => 0.999)).toBeLessThan(MAX_STAGGER_MS);
    expect(staggerOffsetMs(60 * 60_000, 50, () => 0.999)).toBeLessThan(50 * STAGGER_PER_SLOT_MS);
    expect(staggerOffsetMs(60 * 60_000, 2, () => 0.999)).toBeLessThan(12_000);
    expect(staggerOffsetMs(8 * 60_000, 500, () => 0.999)).toBeLessThan(2 * 60_000);
    expect(staggerOffsetMs(0, 50, () => 0.5)).toBe(0);
    expect(staggerOffsetMs(null, 50, () => 0)).toBe(0);
    const spread = new Set(Array.from({ length: 50 }, (_, i) => staggerOffsetMs(60 * 60_000, 50, () => i / 50)));
    expect(spread.size).toBe(50);
  });

  it("stops a ring above 20 % failures once 10 results are in", () => {
    expect(ringShouldStop(5, 4)).toBe(false); // only 9 results
    expect(ringShouldStop(8, 2)).toBe(false); // exactly 20 %
    expect(ringShouldStop(7, 3)).toBe(true);
    expect(ringShouldStop(0, 10)).toBe(true);
  });
});

describe("retry backoff", () => {
  it("doubles per generation with jitter and a 60-minute cap", () => {
    expect(retryDelayMs(0, () => 0.5)).toBe(60_000);
    expect(retryDelayMs(3, () => 0.5)).toBe(8 * 60_000);
    expect(retryDelayMs(20, () => 0.5)).toBe(60 * 60_000);
    expect(retryDelayMs(1, () => 0)).toBe(Math.round(2 * 60_000 * 0.8));
    expect(retryDelayMs(1, () => 1)).toBe(Math.round(2 * 60_000 * 1.2));
  });
});
