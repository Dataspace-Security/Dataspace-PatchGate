import { describe, expect, it } from "vitest";
import { packageInputSchema, parseInstallResult, toInstallEnv } from "./package-input";

const msi = {
  kind: "msi" as const,
  wingetId: "Google.Chrome",
  version: "130.0.6723.59",
  sha256: "a".repeat(64),
  repoPath: "pkgs/Google.Chrome/130.0.6723.59/Google.Chrome-130.0.6723.59.msi",
  publisher: "O=Google LLC",
};
const exe = {
  kind: "exe" as const,
  wingetId: "Git.Git",
  version: "2.55.0.5",
  sha256: "b".repeat(64),
  repoPath: "pkgs/Git.Git/2.55.0.5/Git.Git-2.55.0.5.exe",
  publisher: "O=Johannes Schindelin",
  switches: "/SP- /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /ALLUSERS",
};
const agent = {
  kind: "agent" as const,
  wingetId: "Tactical.Agent" as const,
  version: "2.11.0",
  sha256: "c".repeat(64),
  repoPath: "tactical/agent/2.11.0/tacticalagent-v2.11.0-windows-amd64.exe",
};

describe("packageInputSchema", () => {
  it("accepts well-formed msi, exe and agent packages", () => {
    for (const p of [msi, exe, agent]) expect(packageInputSchema.safeParse(p).success, p.kind).toBe(true);
  });

  it.each([
    ["version with injected parameter", { ...msi, version: "1.0 -SkipVerify" }],
    ["version with command separator", { ...msi, version: "1.0;iex(evil)" }],
    ["winget id with $()", { ...msi, wingetId: "Foo.$(calc)" }],
    ["uppercase/short sha", { ...msi, sha256: "ABC" }],
    ["path traversal", { ...msi, repoPath: "pkgs/../../windows/system32/x.msi" }],
    ["absolute path", { ...msi, repoPath: "/etc/passwd" }],
    ["backslash path", { ...msi, repoPath: "pkgs\\x.msi" }],
    ["UNC path", { ...msi, repoPath: "//evil/share/x.msi" }],
    ["publisher with quote/semicolon", { ...msi, publisher: 'x"; calc' }],
    ["msi path with exe extension", { ...msi, repoPath: "pkgs/a/1/a.exe" }],
    ["exe with value switch", { ...exe, switches: "/S /D=C:\\evil" }],
    ["exe with non-normalised switches", { ...exe, switches: "/S  /NORESTART" }],
    ["exe outside pkgs/", { ...exe, repoPath: "tactical/agent/x.exe" }],
    ["agent outside tactical/agent", { ...agent, repoPath: "pkgs/Tactical.Agent/2.11.0/x.exe" }],
    ["agent with switches", { ...agent, switches: "/S" }],
    ["agent pretending to be another app", { ...agent, wingetId: "Google.Chrome" }],
    ["unknown kind", { ...msi, kind: "script" }],
  ])("rejects %s", (_name, p) => {
    expect(packageInputSchema.safeParse(p).success).toBe(false);
  });
});

describe("toInstallEnv", () => {
  it("maps validated values to env vars", () => {
    expect(toInstallEnv(exe, "https://patchgate.bank.local/repo")).toEqual({
      PG_KIND: "exe",
      PG_REPO_URL: "https://patchgate.bank.local/repo",
      PG_PATH: exe.repoPath,
      PG_SHA256: exe.sha256,
      PG_APP_ID: exe.wingetId,
      PG_VERSION: exe.version,
      PG_PUBLISHER: exe.publisher,
      PG_ARGS: exe.switches,
    });
    expect(toInstallEnv(agent, "https://x").PG_PUBLISHER).toBe("");
  });

  it("throws on invalid input instead of passing it through", () => {
    expect(() => toInstallEnv({ ...msi, version: "1 & del" }, "https://x")).toThrow();
  });
});

describe("parseInstallResult", () => {
  it("accepts only an explicit OK line", () => {
    expect(parseInstallResult("downloading...\r\nPATCHGATE_RESULT=OK\r\n")).toEqual({ ok: true });
  });
  it("surfaces script failure reasons", () => {
    expect(parseInstallResult("PATCHGATE_RESULT=FAIL:hash mismatch")).toEqual({ ok: false, reason: "FAIL:hash mismatch" });
  });
  it("treats missing result line as failure", () => {
    expect(parseInstallResult("timeout").ok).toBe(false);
  });
});
