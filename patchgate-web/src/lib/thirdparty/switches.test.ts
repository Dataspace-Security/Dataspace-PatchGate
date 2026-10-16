import { describe, expect, it } from "vitest";
import { ALLOWED_SWITCHES, silentSwitchesFor, validateSwitches } from "./switches";

describe("validateSwitches", () => {
  it("accepts allow-listed tokens and normalises spacing", () => {
    expect(validateSwitches("  /SP-   /VERYSILENT /SUPPRESSMSGBOXES /NORESTART ")).toBe("/SP- /VERYSILENT /SUPPRESSMSGBOXES /NORESTART");
    expect(validateSwitches("/S")).toBe("/S");
    expect(validateSwitches("/quiet /norestart")).toBe("/quiet /norestart");
  });

  it.each([
    ["value switch (install dir)", "/S /D=C:\\evil"],
    ["log path", "/VERYSILENT /LOG=C:\\x.txt"],
    ["unknown token", "/S /EVIL"],
    ["shell metachar", "/S & calc"],
    ["quotes", '/S "x"'],
    ["empty", "   "],
    ["too many tokens", Array(13).fill("/S").join(" ")],
  ])("rejects %s", (_n, s) => {
    expect(validateSwitches(s)).toBeNull();
  });

  it("allow-list contains only flag-style tokens (no '=' or values)", () => {
    for (const t of ALLOWED_SWITCHES) expect(t).toMatch(/^(\/|--?)[A-Za-z-]+$/);
  });
});

describe("silentSwitchesFor", () => {
  it("uses fixed defaults per installer technology", () => {
    expect(silentSwitchesFor("nullsoft", "machine", null)).toBe("/S");
    expect(silentSwitchesFor("inno", "machine", null)).toBe("/SP- /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /ALLUSERS");
    expect(silentSwitchesFor("inno", "", null)).toBe("/SP- /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /ALLUSERS");
    expect(silentSwitchesFor("burn", "machine", null)).toBe("/quiet /norestart");
  });

  it("for generic exe uses the manifest's Silent switches only if fully allow-listed", () => {
    expect(silentSwitchesFor("exe", "machine", "/S")).toBe("/S");
    expect(silentSwitchesFor("exe", "machine", "/S /D=C:\\x")).toBeNull();
    expect(silentSwitchesFor("exe", "machine", null)).toBeNull();
  });

  it("ignores manifest switches for known technologies (fixed defaults win)", () => {
    expect(silentSwitchesFor("nullsoft", "machine", "/S /D=C:\\evil")).toBe("/S");
  });

  it("rejects unknown technologies (msix, portable, zip...)", () => {
    expect(silentSwitchesFor("msix", "machine", null)).toBeNull();
    expect(silentSwitchesFor("portable", "machine", "/S")).toBeNull();
  });
});

describe("PC-side script stays in sync", () => {
  it("Install-PatchGatePackage.ps1 allows exactly the same switches", async () => {
    const { readFileSync } = await import("node:fs");
    const { fileURLToPath } = await import("node:url");
    const ps = readFileSync(fileURLToPath(new URL("../../../scripts/endpoint/Install-PatchGatePackage.ps1", import.meta.url)), "utf8");
    const block = /\$AllowedSwitches = @\(([\s\S]*?)\)/.exec(ps)?.[1] ?? "";
    const psTokens = [...block.matchAll(/'([^']+)'/g)].map((m) => m[1]).sort();
    expect(psTokens).toEqual([...ALLOWED_SWITCHES].sort());
  });
});
