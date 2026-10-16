import { describe, expect, it } from "vitest";
import { jobPayloadSchemas, resultSchemas, JOB_TYPES, TACTICAL_SERVICE_USERNAME } from "./protocol";
import { approvalDriftKey, auditDedupeKey, describeActivity, foreignApprovals, isOutOfBandEvent, parseOccurredAt } from "./tactical-activity-rules";
import { EVENT_INFO, isCritical, toggleableEvents } from "@/lib/notify/events";
import { renderMessage } from "@/lib/notify/templates";

const now = new Date("2026-10-16T12:00:00Z");

describe("protocol: TACTICAL_AUDIT_SYNC", () => {
  it("is a known job type with a strict, bounded payload and result", () => {
    expect(JOB_TYPES).toContain("TACTICAL_AUDIT_SYNC");
    expect(jobPayloadSchemas.TACTICAL_AUDIT_SYNC.safeParse({ afterId: 12, limit: 500 }).success).toBe(true);
    expect(jobPayloadSchemas.TACTICAL_AUDIT_SYNC.safeParse({ afterId: 12, limit: 500, endpoint: "/accounts/users/" }).success).toBe(false);
    expect(resultSchemas.TACTICAL_AUDIT_SYNC.safeParse({ events: [], cursor: 0, more: false }).success).toBe(true);
    expect(resultSchemas.TACTICAL_AUDIT_SYNC.safeParse({ events: [{ id: 0, ts: "", actor: "", action: "", objectType: "", agentHostname: null, agentId: null, message: null, ip: null }], cursor: 0, more: false }).success).toBe(false);
  });
});

describe("Tactical seal rules", () => {
  it("drops the service account's own API work, keeps every human action and any login as the service account", () => {
    expect(isOutOfBandEvent({ actor: TACTICAL_SERVICE_USERNAME, action: "execute_script" })).toBe(false);
    expect(isOutOfBandEvent({ actor: TACTICAL_SERVICE_USERNAME, action: "failed_login" })).toBe(true);
    expect(isOutOfBandEvent({ actor: "tacticaladmin", action: "login" })).toBe(true);
    expect(isOutOfBandEvent({ actor: "site-root (break-glass)", action: "modify" })).toBe(true);
  });

  it("parses Tactical entry times, falls back to now for garbage or far-future values", () => {
    expect(parseOccurredAt("2026-10-16T10:05:00.123456+02:00", now).toISOString()).toBe("2026-10-16T08:05:00.123Z");
    expect(parseOccurredAt("not a date", now)).toEqual(now);
    expect(parseOccurredAt("2030-01-01T00:00:00Z", now)).toEqual(now);
  });

  it("de-duplication keys: audit id + time; drift per PC + guid set (order/case insensitive) + day", () => {
    const t = new Date("2026-10-16T10:00:00Z");
    expect(auditDedupeKey(7, t)).toBe("audit:7:2026-10-16T10:00:00.000Z");
    const a = approvalDriftKey("agentA", ["AAAA-1", "bbbb-2"], t);
    expect(approvalDriftKey("agentA", ["bbbb-2", "aaaa-1"], new Date("2026-10-16T23:00:00Z"))).toBe(a);
    expect(approvalDriftKey("agentA", ["bbbb-2"], t)).not.toBe(a);
    expect(approvalDriftKey("agentA", ["AAAA-1", "bbbb-2"], new Date("2026-10-17T00:00:01Z"))).not.toBe(a);
  });

  it("foreign approvals: pending approvals PatchGate did not set (installed and not-approved ignored)", () => {
    const u = (guid: string, action: string, installed = false) => ({ guid, kb: null, action, installed });
    const list = [u("G1", "approve"), u("G2", "approve"), u("G3", "approve", true), u("G4", "nothing"), u("G5", "inherit")];
    expect(foreignApprovals(list, new Set(["g1"])).map((x) => x.guid)).toEqual(["G2"]);
    expect(foreignApprovals(list, undefined).map((x) => x.guid)).toEqual(["G1", "G2"]);
  });

  it("describes activities in one line (live case: KB890830 approved on DESKTOP-Q6U5I2R)", () => {
    expect(describeActivity({ actor: "tacticaladmin", action: "login", objectType: "user", agentHostname: null, message: null })).toBe("tacticaladmin: dashboard login");
    expect(
      describeActivity({ actor: "unknown", action: "winupdate_approve", objectType: "winupdate", agentHostname: "DESKTOP-Q6U5I2R", message: "1 update approval(s) set outside PatchGate: KB890830" }),
    ).toBe("unknown: approved Windows updates on DESKTOP-Q6U5I2R — 1 update approval(s) set outside PatchGate: KB890830");
    expect(describeActivity({ actor: "x", action: "modify", objectType: "winupdatepolicy", agentHostname: null, message: null })).toBe("x: changed winupdatepolicy");
  });
});

describe("TACTICAL_OUT_OF_BAND notification", () => {
  it("is critical (cannot be switched off), reaches bank + platform, renders without secrets", () => {
    expect(isCritical("TACTICAL_OUT_OF_BAND")).toBe(true);
    expect(EVENT_INFO.TACTICAL_OUT_OF_BAND).toMatchObject({ bank: true, platform: true });
    expect(toggleableEvents("bank")).not.toContain("TACTICAL_OUT_OF_BAND");
    const m = renderMessage("TACTICAL_OUT_OF_BAND", { bankName: "Bank A", connectorName: "HQ", total: 2, problem: "tacticaladmin: dashboard login" }, "https://pg.example");
    expect(m.subject).toBe("[PatchGate] CRITICAL: 2 action(s) in Tactical outside PatchGate: HQ — Bank A");
    expect(m.text).toContain("Latest: tacticaladmin: dashboard login");
    expect(m.link).toBe("https://pg.example/connectors");
  });
});
