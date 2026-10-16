import { describe, expect, it } from "vitest";
import { buildDeployPlan, checkApprovalState, windowsInstallComplete } from "./deploy-plan";
import type { TacticalWinUpdate } from "./types";

function upd(p: Partial<TacticalWinUpdate> & { id: number; guid: string }): TacticalWinUpdate {
  return { kb: null, title: "t", installed: false, action: "nothing", severity: null, ...p };
}

describe("buildDeployPlan", () => {
  it("approves only the approved GUIDs that are not installed", () => {
    const plan = buildDeployPlan(
      [upd({ id: 1, guid: "a" }), upd({ id: 2, guid: "b" }), upd({ id: 3, guid: "c", installed: true })],
      new Set(["a", "c"]),
    );
    expect(plan.toApprove).toEqual([1]);
    expect(plan.installTargets).toEqual(["a"]);
  });

  it("resets any other update Tactical has marked approve (install endpoint installs ALL approved)", () => {
    const plan = buildDeployPlan(
      [
        upd({ id: 1, guid: "a" }),
        upd({ id: 2, guid: "b", action: "approve" }), // stale approval — must be cleared
        upd({ id: 3, guid: "c", action: "inherit" }),
      ],
      new Set(["a"]),
    );
    expect(plan.toReset).toEqual([2, 3]);
  });

  it("does not touch updates that already have the right action", () => {
    const plan = buildDeployPlan(
      [upd({ id: 1, guid: "a", action: "approve" }), upd({ id: 2, guid: "b", action: "ignore" })],
      new Set(["a"]),
    );
    expect(plan.toApprove).toEqual([]);
    expect(plan.toReset).toEqual([]);
    expect(plan.installTargets).toEqual(["a"]);
  });

  it("reports approved GUIDs the agent does not know about (needs rescan)", () => {
    const plan = buildDeployPlan([upd({ id: 1, guid: "a" })], new Set(["a", "z"]));
    expect(plan.missingOnAgent).toEqual(["z"]);
  });

  it("is a no-op install when nothing is pending", () => {
    const plan = buildDeployPlan([upd({ id: 1, guid: "a", installed: true })], new Set(["a"]));
    expect(plan.installTargets).toEqual([]);
  });
});

describe("checkApprovalState", () => {
  it("passes when Tactical's approved-and-pending set equals our targets", () => {
    const ups = [
      upd({ id: 1, guid: "a", action: "approve" }),
      upd({ id: 2, guid: "b", action: "nothing" }),
      upd({ id: 3, guid: "c", action: "approve", installed: true }),
    ];
    expect(checkApprovalState(ups, ["a"])).toEqual({ ok: true });
  });

  it("flags foreign approvals Tactical re-applied (e.g. patch policy not manual)", () => {
    const ups = [upd({ id: 1, guid: "a", action: "approve" }), upd({ id: 2, guid: "x", action: "approve" })];
    expect(checkApprovalState(ups, ["a"])).toEqual({ ok: false, unexpected: ["x"], missing: [] });
  });

  it("flags our targets that did not stick", () => {
    const ups = [upd({ id: 1, guid: "a", action: "nothing" })];
    expect(checkApprovalState(ups, ["a"])).toEqual({ ok: false, unexpected: [], missing: ["a"] });
  });
});

describe("windowsInstallComplete", () => {
  it("is complete only when every GUID is present AND installed", () => {
    const ups = [upd({ id: 1, guid: "a", installed: true }), upd({ id: 2, guid: "b", installed: true })];
    expect(windowsInstallComplete(ups, ["a", "b"])).toBe(true);
  });

  it("treats a GUID the agent does not report as NOT installed", () => {
    expect(windowsInstallComplete([upd({ id: 1, guid: "a", installed: true })], ["a", "z"])).toBe(false);
  });

  it("is trivially complete with no Windows patches", () => {
    expect(windowsInstallComplete([], [])).toBe(true);
  });
});

describe("GUID case-insensitivity (WSUS vs agent casing)", () => {
  it("matches approved lowercase GUIDs to uppercase agent GUIDs everywhere", () => {
    const ups = [upd({ id: 1, guid: "ABCD-1" })];
    const plan = buildDeployPlan(ups, new Set(["abcd-1"]));
    expect(plan.toApprove).toEqual([1]);
    expect(plan.missingOnAgent).toEqual([]);
    expect(checkApprovalState([upd({ id: 1, guid: "ABCD-1", action: "approve" })], plan.installTargets)).toEqual({ ok: true });
    expect(windowsInstallComplete([upd({ id: 1, guid: "ABCD-1", installed: true })], ["abcd-1"])).toBe(true);
  });
});
