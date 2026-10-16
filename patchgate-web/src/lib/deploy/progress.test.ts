import { describe, expect, it } from "vitest";
import { deploymentStage, percentOf, progressFromCounts, rolloutProgress, waitReason } from "./progress";

describe("deployment stage", () => {
  it("maps finished states", () => {
    expect(deploymentStage({ status: "SUCCEEDED" })).toBe("succeeded");
    expect(deploymentStage({ status: "FAILED" })).toBe("failed");
    expect(deploymentStage({ status: "TIMED_OUT" })).toBe("failed");
  });

  it("derives waiting stages from the pump's notes (connector-state WAITING_NOTE_PREFIX)", () => {
    expect(deploymentStage({ status: "QUEUED", note: "waiting for Windows update files: 2 file(s) still downloading / verifying" })).toBe("downloading");
    expect(deploymentStage({ status: "QUEUED", note: "waiting for the site cache" })).toBe("caching");
    expect(deploymentStage({ status: "SENDING", note: "waiting for the site cache" })).toBe("caching");
    expect(deploymentStage({ status: "QUEUED", note: "endpoint busy with another change request" })).toBe("queued");
    expect(deploymentStage({ status: "QUEUED" })).toBe("queued");
  });

  it("uses the active connector job", () => {
    expect(deploymentStage({ status: "SENDING", activeJobType: "CACHE_PACKAGE" })).toBe("caching");
    expect(deploymentStage({ status: "SENDING", activeJobType: "WU_INSTALL" })).toBe("installing");
    expect(deploymentStage({ status: "SENDING", activeJobType: "DEPLOY_PACKAGE" })).toBe("installing");
    expect(deploymentStage({ status: "SENDING" })).toBe("installing");
  });

  it("SENT: reboot pending when the PC needs a restart, else still installing / confirming", () => {
    expect(deploymentStage({ status: "SENT", rebootRequired: true })).toBe("reboot");
    expect(deploymentStage({ status: "SENT" })).toBe("installing");
  });

  it("wait reason only for unfinished deployments", () => {
    expect(waitReason({ status: "QUEUED", note: " waiting for the site cache " })).toBe("waiting for the site cache");
    expect(waitReason({ status: "QUEUED", note: null })).toBeNull();
    expect(waitReason({ status: "SUCCEEDED", note: "nothing to install on this PC" })).toBeNull();
  });
});

describe("rollout progress", () => {
  it("counts segments and percent finished (succeeded + failed)", () => {
    const p = rolloutProgress([
      { status: "SUCCEEDED" },
      { status: "SUCCEEDED" },
      { status: "FAILED" },
      { status: "SENDING", activeJobType: "WU_INSTALL" },
      { status: "SENT", rebootRequired: true },
      { status: "QUEUED", note: "waiting for the site cache" },
      { status: "QUEUED" },
      { status: "TIMED_OUT" },
    ]);
    expect(p).toMatchObject({ total: 8, succeeded: 2, failed: 2, inProgress: 2, queued: 2, finished: 4, percent: 50 });
    expect(p.stages).toEqual({ queued: 1, downloading: 0, caching: 1, installing: 1, reboot: 1, succeeded: 2, failed: 2 });
  });

  it("empty rollout is 0 %, never NaN", () => {
    expect(rolloutProgress([])).toMatchObject({ total: 0, percent: 0 });
  });

  it("100 % only when everything finished; rounding never shows 100 early", () => {
    expect(percentOf(999, 1000)).toBe(99);
    expect(percentOf(1000, 1000)).toBe(100);
    expect(percentOf(1, 3)).toBe(33);
  });

  it("from grouped status counts (change-requests list)", () => {
    const p = progressFromCounts({ SUCCEEDED: 3, FAILED: 1, TIMED_OUT: 1, QUEUED: 4, SENDING: 1 });
    expect(p).toMatchObject({ total: 10, succeeded: 3, failed: 2, queued: 4, inProgress: 1, percent: 50 });
  });
});
