import { describe, expect, it } from "vitest";
import { compareVersions, findOutdated, isInstalledAtLeast } from "./version";

describe("compareVersions", () => {
  it.each([
    ["130.0.6723.59", "128.0.6613.120", 1],
    ["1.2", "1.10", -1],
    ["24.002.20933", "24.002.20933", 0],
    ["1.0", "1.0.0", 0],
    ["23.01", "23.1", 0],
  ])("%s vs %s -> %i", (a, b, expected) => {
    expect(Math.sign(compareVersions(a, b))).toBe(expected);
  });

  it("ignores non-numeric suffixes safely", () => {
    expect(compareVersions("8.0.432-b06", "8.0.431")).toBeGreaterThan(0);
  });
});

describe("findOutdated", () => {
  const apps = [
    { appId: "chrome", inventoryMatch: "^Google Chrome$", approvedVersion: "130.0.6723.59" },
    { appId: "7zip", inventoryMatch: "^7-Zip", approvedVersion: "24.08" },
  ];

  it("returns apps installed at a lower version than approved", () => {
    const inv = [
      { name: "Google Chrome", version: "128.0.6613.120" },
      { name: "7-Zip 24.08 (x64)", version: "24.08" },
      { name: "Notepad", version: "1" },
    ];
    expect(findOutdated(inv, apps)).toEqual([
      { appId: "chrome", installedVersion: "128.0.6613.120", approvedVersion: "130.0.6723.59" },
    ]);
  });

  it("ignores apps that are not installed (we patch, we don't push new software)", () => {
    expect(findOutdated([], apps)).toEqual([]);
  });

  it("does not crash on an invalid admin-supplied regex", () => {
    const bad = [{ appId: "x", inventoryMatch: "(", approvedVersion: "1" }];
    expect(findOutdated([{ name: "(", version: "0" }], bad)).toEqual([]);
  });
});

describe("isInstalledAtLeast", () => {
  const inv = [{ name: "Google Chrome", version: "130.0.6723.59" }];
  it("true when installed version >= target", () => {
    expect(isInstalledAtLeast(inv, "^Google Chrome$", "130.0.6723.59")).toBe(true);
    expect(isInstalledAtLeast(inv, "^Google Chrome$", "129")).toBe(true);
  });
  it("false when older or absent", () => {
    expect(isInstalledAtLeast(inv, "^Google Chrome$", "131")).toBe(false);
    expect(isInstalledAtLeast(inv, "^Firefox", "1")).toBe(false);
  });
});

describe("compareVersions robustness", () => {
  it.each([
    ["v2.9.0", "2.8.0", 1],
    ["v2.11.0", "2.11.0", 0],
    ["2.11.0-rc1", "2.11.0", 0],
    ["2.x.1", "2.0.1", 0],
    ["2.10.0", "2.9.9", 1],
  ])("%s vs %s -> %i (segments keep their position)", (a, b, expected) => {
    expect(Math.sign(compareVersions(a, b))).toBe(expected);
  });
});
