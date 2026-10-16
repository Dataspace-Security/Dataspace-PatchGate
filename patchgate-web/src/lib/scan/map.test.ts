import { describe, expect, it } from "vitest";
import { mapSeverity, thirdPartyStatus } from "./map";

describe("mapSeverity", () => {
  it.each([
    ["Critical", "CRITICAL"],
    ["important", "IMPORTANT"],
    ["Moderate", "MODERATE"],
    ["Low", "LOW"],
    ["", "UNSPECIFIED"],
    [null, "UNSPECIFIED"],
    ["weird", "UNSPECIFIED"],
  ])("%s -> %s", (input, expected) => {
    expect(mapSeverity(input)).toBe(expected);
  });
});

describe("thirdPartyStatus", () => {
  const inv = [{ name: "Google Chrome", version: "128.0.1" }];
  it("NEEDED when installed below the approved version", () => {
    expect(thirdPartyStatus(inv, "^Google Chrome$", "130.0")).toBe("NEEDED");
  });
  it("INSTALLED when at or above", () => {
    expect(thirdPartyStatus(inv, "^Google Chrome$", "128.0.1")).toBe("INSTALLED");
  });
  it("null when the app is not installed at all (we patch, never push new software)", () => {
    expect(thirdPartyStatus(inv, "^Firefox", "1")).toBeNull();
  });
});
