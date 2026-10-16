import { describe, expect, it } from "vitest";
import { CACHE_RETRY_AFTER_MS, FAILED_RETRY_AFTER_MS, MAX_CACHE_FAILURES, currentAgentBuildPackages, deriveCacheState } from "./connector-cache";
import { deployDeadlineDays, deployDeadlineFrom, DEFAULT_DEPLOY_DEADLINE_DAYS } from "./deadline";
import { expectedGuidsOfJob } from "./connector-state";

const t = new Date("2026-10-15T00:00:00Z");
const row = (status: string, processed = true, completedAt: Date | null = t, error: string | null = null) => ({
  id: `j${Math.random()}`,
  sha256: "a".repeat(64),
  status,
  processedAt: processed ? t : null,
  completedAt,
  error,
});

describe("deriveCacheState (M4)", () => {
  it("no history / expired → start a download; live or unapplied → pending; applied success → cached", () => {
    expect(deriveCacheState([]).state).toBeNull();
    expect(deriveCacheState([row("EXPIRED")]).state).toBeNull();
    expect(deriveCacheState([row("QUEUED", false, null)]).state).toMatchObject({ state: "pending" });
    expect(deriveCacheState([row("FAILED", false)]).state).toMatchObject({ state: "pending" });
    expect(deriveCacheState([row("SUCCEEDED")]).state).toEqual({ state: "cached" });
  });

  it("a failure under the cap defers (pending, retry after CACHE_RETRY_AFTER_MS); the cap fails (retry after FAILED_RETRY_AFTER_MS)", () => {
    const one = deriveCacheState([row("FAILED", true, t, "boom")]);
    expect(one.state).toEqual({ state: "pending", jobId: null });
    expect(one.retryAt?.getTime()).toBe(t.getTime() + CACHE_RETRY_AFTER_MS);

    const capped = deriveCacheState(Array.from({ length: MAX_CACHE_FAILURES }, () => row("FAILED", true, t, "boom")));
    expect(capped.state).toEqual({ state: "failed", error: "boom" });
    expect(capped.retryAt?.getTime()).toBe(t.getTime() + FAILED_RETRY_AFTER_MS);

    // failures before an earlier success do not count
    const reset = deriveCacheState([row("FAILED"), row("SUCCEEDED"), row("FAILED"), row("FAILED")]);
    expect(reset.state).toMatchObject({ state: "pending" });
  });
});

describe("deployment deadline (M3)", () => {
  it("defaults to 14 days and ignores invalid values", () => {
    expect(deployDeadlineDays(undefined)).toBe(DEFAULT_DEPLOY_DEADLINE_DAYS);
    expect(deployDeadlineDays("7")).toBe(7);
    expect(deployDeadlineDays("0")).toBe(DEFAULT_DEPLOY_DEADLINE_DAYS);
    expect(deployDeadlineDays("abc")).toBe(DEFAULT_DEPLOY_DEADLINE_DAYS);
    expect(deployDeadlineDays("365")).toBe(DEFAULT_DEPLOY_DEADLINE_DAYS);
    expect(deployDeadlineFrom(t, 2).getTime()).toBe(t.getTime() + 2 * 86_400_000);
  });
});

describe("expectedGuidsOfJob (M1 / H5)", () => {
  it("returns what the install job was meant to install", () => {
    expect(expectedGuidsOfJob("DEPLOY_WINDOWS", { agentId: "a", guids: ["g1", "g2"] })).toEqual(["g1", "g2"]);
    expect(expectedGuidsOfJob("WU_INSTALL", { agentId: "a", updates: [{ updateId: "u1" }, { updateId: "u2" }] })).toEqual(["u1", "u2"]);
    expect(expectedGuidsOfJob("DEPLOY_PACKAGE", { agentId: "a" })).toEqual([]);
    expect(expectedGuidsOfJob("WU_INSTALL", null)).toEqual([]);
  });
});

describe("currentAgentBuildPackages (post-enrolment site cache)", () => {
  const row = (version: string, arch: string, sha: string) => ({
    version,
    assetName: `tacticalagent-v${version}-windows-${arch}.exe`,
    sha256: sha.repeat(64),
    repoPath: `tactical/agent/${version}/tacticalagent-v${version}-windows-${arch}.exe`,
    sizeBytes: BigInt(1234),
  });

  it("takes the NEWEST verified version (numeric order), both architectures", () => {
    const pkgs = currentAgentBuildPackages([row("2.9.0", "amd64", "a"), row("2.10.0", "amd64", "b"), row("2.10.0", "386", "c"), row("2.9.0", "386", "d")]);
    expect(pkgs.map((p) => [p.version, p.sha256[0], p.kind, p.size])).toEqual([
      ["2.10.0", "b", "agent", 1234],
      ["2.10.0", "c", "agent", 1234],
    ]);
  });

  it("returns what exists for one arch, nothing for no rows, and skips paths outside the allow-list", () => {
    expect(currentAgentBuildPackages([row("2.10.0", "amd64", "b")])).toHaveLength(1);
    expect(currentAgentBuildPackages([])).toEqual([]);
    expect(currentAgentBuildPackages([{ ...row("2.10.0", "amd64", "b"), repoPath: "pkgs/evil/x.exe" }])).toEqual([]);
    expect(currentAgentBuildPackages([{ ...row("2.10.0", "amd64", "b"), version: "latest" }])).toEqual([]);
  });
});
