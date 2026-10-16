import { describe, expect, it } from "vitest";
import { WINGET_ID_RE, installerManifestUrl, manifestDirFor, pickLatestVersion, repoSegment, selectInstaller } from "./winget";

// Trimmed from the real Google.Chrome 155.0.8059.40 manifest (microsoft/winget-pkgs).
const CHROME = `
PackageIdentifier: Google.Chrome
PackageVersion: 155.0.8059.40
InstallerType: wix
Scope: machine
Installers:
- Architecture: x86
  InstallerUrl: https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise.msi
  InstallerSha256: 7DE1A4D079B0C5B167CB1BFCE41CE554EFB71C98D3F5150351C7EE147C10B20E
- Architecture: x64
  InstallerUrl: https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise64.msi
  InstallerSha256: 32BA438DEA18F0FED1EC621BFB274A2669ADEC67BE2AA91D96B3CC6C64779276
  ProductCode: '{AE41646D-561A-3316-9B94-DD3EA96EF975}'
ManifestType: installer
`;

describe("manifestDirFor", () => {
  it.each([
    ["Google.Chrome", "manifests/g/Google/Chrome"],
    ["Mozilla.Firefox.ESR", "manifests/m/Mozilla/Firefox/ESR"],
    ["7zip.7zip", "manifests/7/7zip/7zip"],
  ])("%s", (id, dir) => expect(manifestDirFor(id)).toBe(dir));

  it("rejects ids that could traverse paths", () => {
    expect(() => manifestDirFor("../evil")).toThrow();
    expect(() => manifestDirFor("Google")).toThrow();
  });
});

describe("pickLatestVersion", () => {
  it("ignores channel folders and picks the highest numeric version", () => {
    expect(pickLatestVersion(["154.0.1", "155.0.8059.40", "Beta", "Canary", "EXE", "99.9"])).toBe("155.0.8059.40");
  });
  it("returns null when there are no versions", () => {
    expect(pickLatestVersion(["Beta"])).toBeNull();
  });
});

describe("installerManifestUrl", () => {
  it("builds the raw GitHub URL", () => {
    expect(installerManifestUrl("Google.Chrome", "155.0.8059.40")).toBe(
      "https://raw.githubusercontent.com/microsoft/winget-pkgs/master/manifests/g/Google/Chrome/155.0.8059.40/Google.Chrome.installer.yaml",
    );
  });
});

describe("selectInstaller", () => {
  it("prefers x64 machine-scope MSI, inherits root InstallerType/Scope, lowercases the hash", () => {
    expect(selectInstaller(CHROME)).toEqual({
      url: "https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise64.msi",
      sha256: "32ba438dea18f0fed1ec621bfb274a2669adec67be2aa91d96b3cc6c64779276",
      productCode: "{AE41646D-561A-3316-9B94-DD3EA96EF975}",
      architecture: "x64",
      kind: "msi",
      installerType: "wix",
      switches: "",
    });
  });

  it("returns null for user-scope only, or a generic EXE without safe switches", () => {
    const exeNoSwitches = `InstallerType: exe\nInstallers:\n- Architecture: x64\n  InstallerUrl: https://x/y.exe\n  InstallerSha256: ${"A".repeat(64)}\n`;
    const userScope = `InstallerType: msi\nScope: user\nInstallers:\n- Architecture: x64\n  InstallerUrl: https://x/y.msi\n  InstallerSha256: ${"A".repeat(64)}\n`;
    expect(selectInstaller(exeNoSwitches)).toBeNull();
    expect(selectInstaller(userScope)).toBeNull();
  });

  it("prefers MSI over EXE even when the EXE is listed first", () => {
    const both = `Installers:\n- Architecture: x64\n  InstallerType: nullsoft\n  Scope: machine\n  InstallerUrl: https://x/a.exe\n  InstallerSha256: ${"A".repeat(64)}\n- Architecture: x64\n  InstallerType: wix\n  Scope: machine\n  InstallerUrl: https://x/a.msi\n  InstallerSha256: ${"B".repeat(64)}\n`;
    expect(selectInstaller(both)?.kind).toBe("msi");
  });

  it("selects an Inno machine-scope EXE (Git for Windows) with FIXED switches, ignoring manifest switches", () => {
    const git = [
      "InstallerType: inno",
      "InstallerSwitches:",
      "  Silent: /SP- /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /LOG=C:\\x",
      "Installers:",
      "- Architecture: x64",
      "  Scope: user",
      "  InstallerUrl: https://github.com/git-for-windows/git/releases/download/v2/Git-64-bit.exe",
      `  InstallerSha256: ${"C".repeat(64)}`,
      "- Architecture: x64",
      "  Scope: machine",
      "  InstallerUrl: https://github.com/git-for-windows/git/releases/download/v2/Git-64-bit.exe",
      `  InstallerSha256: ${"C".repeat(64)}`,
    ].join("\n");
    expect(selectInstaller(git)).toMatchObject({
      kind: "exe",
      installerType: "inno",
      switches: "/SP- /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /ALLUSERS",
    });
  });

  it("selects a generic EXE (7-Zip) only with allow-listed per-installer switches", () => {
    const sevenZip = [
      "Scope: machine",
      "Installers:",
      "- Architecture: x64",
      "  InstallerType: exe",
      "  InstallerUrl: https://www.7-zip.org/a/7z2604-x64.exe",
      `  InstallerSha256: ${"D".repeat(64)}`,
      "  InstallerSwitches:",
      "    Silent: /S",
    ].join("\n");
    expect(selectInstaller(sevenZip)).toMatchObject({
      kind: "exe",
      installerType: "exe",
      switches: "/S",
      url: "https://www.7-zip.org/a/7z2604-x64.exe",
    });
  });

  it("rejects malformed hashes", () => {
    const bad = `InstallerType: msi\nInstallers:\n- Architecture: x64\n  InstallerUrl: https://x/y.msi\n  InstallerSha256: nothex\n`;
    expect(selectInstaller(bad)).toBeNull();
  });
});

describe("real-world winget ids", () => {
  it("accepts ids with + (Notepad++.Notepad++) and builds the right manifest dir", () => {
    expect(manifestDirFor("Notepad++.Notepad++")).toBe("manifests/n/Notepad++/Notepad++");
    expect(WINGET_ID_RE.test("Notepad++.Notepad++")).toBe(true);
    expect(WINGET_ID_RE.test("EclipseAdoptium.Temurin.21.JRE")).toBe(true);
  });
  it.each(["Foo.$(calc)", "a/b.c", "../x.y", "Foo.Bar;rm", "Foo .Bar", "NoDot"])("rejects %s", (id) => {
    expect(WINGET_ID_RE.test(id)).toBe(false);
  });
  it("maps ids to strict repo path segments", () => {
    expect(repoSegment("Notepad++.Notepad++")).toBe("Notepad__.Notepad__");
    expect(repoSegment("Google.Chrome")).toBe("Google.Chrome");
  });
});
