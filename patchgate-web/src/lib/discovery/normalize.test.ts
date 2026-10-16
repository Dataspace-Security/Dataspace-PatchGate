import { describe, expect, it } from "vitest";
import { discoveryKey, inventoryRegexFor, productStem, normalizeName, normalizePublisher, productCodeFromUninstall } from "./normalize";

describe("normalizeName (matches winget index forms)", () => {
  it.each([
    ["7-Zip 19.00 (x64)", "7zip(X64)"],
    ["7-Zip 26.01 (x64 edition)", "7zipedition(X64)"],
    ["Git version 2.22.0.windows.1", "git"],
    ["Mozilla Firefox (x64 en-US)", "mozillafirefox(X64)"],
    ["Wireshark 4.6.6 x64", "wireshark(X64)"],
    ["PuTTY release 0.82 (64-bit)", "putty(X64)"],
    ["Zoom Workplace (64-bit)", "zoomworkplace(X64)"],
    ["Notepad++ (64-bit x64)", "notepad(X64)"],
    ["PowerShell 7-x64", "powershell7(X64)"],
    ["Google Chrome", "googlechrome"],
    ["VLC media player", "vlcmediaplayer"],
    ["Amazon Corretto 8 (x86)", "amazoncorretto8(X86)"],
  ])("%s → %s", (raw, expected) => {
    expect(normalizeName(raw).indexed).toBe(expected);
  });
  it("exposes base and arch separately", () => {
    expect(normalizeName("7-Zip 19.00 (x64)")).toEqual({ base: "7zip", arch: "X64", indexed: "7zip(X64)" });
  });
});

describe("normalizePublisher", () => {
  it.each([
    ["Microsoft Corporation", "microsoft"],
    ["Google LLC", "google"],
    ["Igor Pavlov", "igorpavlov"],
    ["Simon Tatham", "simontatham"],
    ["Zoom Video Communications, Inc.", "zoomvideocommunications"],
    ["The Wireshark developer community, https://www.wireshark.org", "thewiresharkdevelopercommunitywwwwiresharkorg"],
    ["Notepad++ Team", "notepadteam"],
    ["Eclipse Adoptium", "eclipseadoptium"],
  ])("%s → %s", (raw, expected) => {
    expect(normalizePublisher(raw)).toBe(expected);
  });
  it("keeps a lone legal word and handles empty input", () => {
    expect(normalizePublisher("Inc")).toBe("inc");
    expect(normalizePublisher("")).toBeNull();
    expect(normalizePublisher(null)).toBeNull();
  });
});

describe("productCodeFromUninstall", () => {
  it("extracts MSI product codes", () => {
    expect(productCodeFromUninstall("MsiExec.exe /X{AE41646D-561A-3316-9B94-DD3EA96EF975}")).toBe("{ae41646d-561a-3316-9b94-dd3ea96ef975}");
    expect(productCodeFromUninstall("MsiExec.exe /I{23170F69-40C1-2702-1900-000001000000}")).toBe("{23170f69-40c1-2702-1900-000001000000}");
    expect(productCodeFromUninstall('"C:\\Windows\\System32\\msiexec.exe" /x {23170F69-40C1-2702-1900-000001000000}')).toBe("{23170f69-40c1-2702-1900-000001000000}");
  });
  it("ignores EXE uninstallers", () => {
    expect(productCodeFromUninstall('"C:\\Program Files\\Git\\unins000.exe"')).toBeNull();
    expect(productCodeFromUninstall(null)).toBeNull();
  });
});

describe("helpers", () => {
  it("builds stable keys", () => {
    expect(discoveryKey("7zip", "igorpavlov")).toBe("7zip|igorpavlov");
    expect(discoveryKey("git", null)).toBe("git|");
  });
  it.each([
    ["Notepad++ (64-bit x64)", "Notepad++ (64-bit x64)", true],
    ["7-Zip 19.00 (x64)", "7-Zip 26.01 (x64)", true],
    ["Git version 2.22.0.windows.1", "Git version 2.55.0", true],
    ["Git version 2.22.0.windows.1", "GitHub Desktop", false],
    ["Mozilla Firefox (x64 en-US)", "Mozilla Firefox (x64 de)", true],
    ["Mozilla Firefox (x64 en-US)", "Mozilla Firefox ESR (x64 en-US)", true],
    ["Wireshark 4.6.6 x64", "Wireshark 4.6.9 x64", true],
    ["PuTTY release 0.82 (64-bit)", "PuTTY release 0.85 (64-bit)", true],
    ["Notepad++ (64-bit x64)", "Notepad++Plugin", false],
  ])("regex from %s vs %s → %s", (from, installed, expected) => {
    expect(new RegExp(inventoryRegexFor(from)).test(installed)).toBe(expected);
  });
  it("derives a version-free product label", () => {
    expect(productStem("7-Zip 26.01 (x64 edition)")).toBe("7-Zip");
    expect(productStem("Git version 2.22.0.windows.1")).toBe("Git");
    expect(productStem("Mozilla Firefox (x64 en-US)")).toBe("Mozilla Firefox");
    expect(productStem("1.2.3")).toBe("1.2.3");
  });
  it("escapes regex metacharacters", () => {
    expect(inventoryRegexFor("Notepad++ (64-bit x64)")).toBe("^Notepad\\+\\+(?![\\w+])");
  });
});
