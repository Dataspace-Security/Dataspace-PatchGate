import { describe, expect, it } from "vitest";
import { eligibilityErrors, type EligiblePatch } from "./eligibility";

const NOW = new Date("2026-10-14T12:00:00Z");

const win: EligiblePatch = {
  title: "KB5050001",
  kind: "WINDOWS",
  supersededById: null,
  appVersion: null,
};

const tp = (over: Partial<NonNullable<EligiblePatch["appVersion"]>> = {}): EligiblePatch => ({
  title: "Chrome 130",
  kind: "THIRD_PARTY",
  supersededById: null,
  appVersion: {
    verification: "VERIFIED",
    repoPath: "pkgs/Google.Chrome/130/chrome.msi",
    availableAt: new Date("2026-10-12T00:00:00Z"),
    version: "130.0.6723.59",
    sha256: "a".repeat(64),
    wingetId: "Google.Chrome",
    publisher: "O=Google LLC",
    installerKind: "MSI",
    silentArgs: "",
    ...over,
  },
});

describe("eligibilityErrors", () => {
  it("accepts current Windows patches and verified, published, released packages", () => {
    expect(eligibilityErrors([win, tp()], NOW)).toEqual([]);
  });

  it("rejects superseded patches", () => {
    expect(eligibilityErrors([{ ...win, supersededById: "p2" }], NOW)[0]).toMatch(/superseded/);
  });

  it("rejects third-party patch with no package", () => {
    expect(eligibilityErrors([{ ...tp(), appVersion: null }], NOW)[0]).toMatch(/no package/);
  });

  it("rejects unverified or unpublished packages", () => {
    expect(eligibilityErrors([tp({ verification: "PENDING" })], NOW)[0]).toMatch(/not verified/);
    expect(eligibilityErrors([tp({ repoPath: null })], NOW)[0]).toMatch(/not published/);
  });

  it("rejects packages still in quarantine", () => {
    const e = eligibilityErrors([tp({ availableAt: new Date("2026-10-20T00:00:00Z") })], NOW);
    expect(e[0]).toMatch(/quarantine/);
  });

  it("rejects packages with values unsafe to send to endpoints", () => {
    expect(eligibilityErrors([tp({ version: "1;calc" })], NOW)[0]).toMatch(/invalid package/);
  });

  it("accepts an EXE package only with allow-listed switches", () => {
    const ok = tp({ installerKind: "EXE", silentArgs: "/S", repoPath: "pkgs/7zip.7zip/26.04/7zip.7zip-26.04.exe" });
    const bad = tp({ installerKind: "EXE", silentArgs: "/S /D=C:\evil", repoPath: "pkgs/7zip.7zip/26.04/7zip.7zip-26.04.exe" });
    expect(eligibilityErrors([ok], NOW)).toEqual([]);
    expect(eligibilityErrors([bad], NOW)[0]).toMatch(/invalid package/);
  });

  it("requires an approved mirrored build for agent upgrades", () => {
    const agent = (rel: EligiblePatch["agentReleases"]): EligiblePatch => ({ title: "Agent 2.11.0", kind: "AGENT_UPGRADE", supersededById: null, appVersion: null, agentReleases: rel });
    expect(eligibilityErrors([agent([])], NOW)[0]).toMatch(/no approved agent build/);
    const build = (arch: string) => ({
      version: "2.11.0",
      sha256: "e".repeat(64),
      repoPath: `tactical/agent/2.11.0/tacticalagent-v2.11.0-windows-${arch}.exe`,
      assetName: `tacticalagent-v2.11.0-windows-${arch}.exe`,
    });
    expect(eligibilityErrors([agent([build("amd64")])], NOW)[0]).toMatch(/both amd64 and 386/);
    expect(eligibilityErrors([agent([build("amd64"), build("386")])], NOW)).toEqual([]);
  });
});

describe("eligibilityErrors per bank", () => {
  it("rejects a third-party package whose app the bank has not enabled", () => {
    expect(eligibilityErrors([{ ...tp(), tenantAppEnabled: false }], NOW)[0]).toMatch(/not enabled for this bank/);
  });

  it("accepts it once the bank has enabled the app (and ignores the flag for Windows patches)", () => {
    expect(eligibilityErrors([{ ...tp(), tenantAppEnabled: true }, { ...win, tenantAppEnabled: false }], NOW)).toEqual([]);
  });
});
