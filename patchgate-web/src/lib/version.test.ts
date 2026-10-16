import { describe, expect, it } from "vitest";
import { PROTOCOL_VERSION } from "@/lib/connector/protocol";
import { buildInfoFrom, encodeBuildId, versionLabel } from "./version";

describe("buildInfoFrom", () => {
  it("decodes a release build id (Next.js deploymentId form) back to the semver version", () => {
    const info = buildInfoFrom({ PATCHGATE_BUILD_ID: "1_0_0-rc2" });
    expect(info).toEqual({ version: "1.0.0-rc2", buildId: "1_0_0-rc2", gitSha: null, protocolVersion: PROTOCOL_VERSION });
    expect(versionLabel(info)).toBe("v1.0.0-rc2");
  });

  it("round-trips dotted pre-releases", () => {
    expect(encodeBuildId("2.10.3-rc.1")).toBe("2_10_3-rc_1");
    expect(buildInfoFrom({ PATCHGATE_BUILD_ID: encodeBuildId("2.10.3-rc.1") }).version).toBe("2.10.3-rc.1");
  });

  it("keeps non-release build ids as they are", () => {
    const info = buildInfoFrom({ PATCHGATE_BUILD_ID: "rc1" });
    expect(info.version).toBe("rc1");
    expect(versionLabel(info)).toBe("rc1");
  });

  it("falls back to dev when unset or not a valid deploymentId", () => {
    expect(buildInfoFrom({}).version).toBe("dev");
    expect(buildInfoFrom({ PATCHGATE_BUILD_ID: "1.0.0" }).buildId).toBe("dev"); // dots are rejected by Next.js
    expect(buildInfoFrom({ PATCHGATE_BUILD_ID: "<script>" }).buildId).toBe("dev");
    expect(versionLabel(buildInfoFrom({}))).toBe("dev");
  });

  it("accepts only hex git shas", () => {
    expect(buildInfoFrom({ PATCHGATE_GIT_SHA: "ABCDEF1234567" }).gitSha).toBe("abcdef1234567");
    expect(buildInfoFrom({ PATCHGATE_GIT_SHA: "not-a-sha" }).gitSha).toBeNull();
    expect(buildInfoFrom({ PATCHGATE_GIT_SHA: "abc" }).gitSha).toBeNull();
  });

  it("returns a frozen object", () => {
    expect(Object.isFrozen(buildInfoFrom({}))).toBe(true);
  });
});
