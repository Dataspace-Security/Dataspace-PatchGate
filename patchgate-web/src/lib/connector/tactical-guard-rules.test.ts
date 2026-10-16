import { describe, expect, it } from "vitest";
import { heartbeatSchema, JOB_TYPES, jobPayloadSchemas, tacticalPushSchema } from "./protocol";
import { auditDrafts, describeActivity, guardResetDraft, guardResetKey } from "./tactical-activity-rules";

/** Real-time Tactical guard (protocol §8): pure rules + protocol shapes (integration: src/test/tactical-guard.int.test.ts). */

const now = new Date("2026-10-16T12:00:00Z");
const G1 = "00000001-0000-4000-8000-000000000000";
const reset = { agentId: "agentAAAA1111", hostname: "PC-T", guid: G1, kb: "KB5000001", title: "Cumulative Update", detectedAt: "2026-10-16T10:42:17.123Z", reset: true, error: null };

describe("protocol additions", () => {
  it("TACTICAL_GUARD_SYNC is a strict, bounded job type", () => {
    expect(JOB_TYPES).toContain("TACTICAL_GUARD_SYNC");
    const ok = { syncId: "gs_abcdefgh", part: 1, parts: 2, allow: [{ agentId: "agentAAAA1111", guids: [G1], until: now.toISOString() }], auditCursor: 3 };
    expect(jobPayloadSchemas.TACTICAL_GUARD_SYNC.safeParse(ok).success).toBe(true);
    expect(jobPayloadSchemas.TACTICAL_GUARD_SYNC.safeParse({ ...ok, part: 3 }).success).toBe(false);
    expect(jobPayloadSchemas.TACTICAL_GUARD_SYNC.safeParse({ ...ok, parts: 51, part: 1 }).success).toBe(false);
    expect(jobPayloadSchemas.TACTICAL_GUARD_SYNC.safeParse({ ...ok, allow: [{ ...ok.allow[0], until: "tomorrow" }] }).success).toBe(false);
  });

  it("push and heartbeat guard status are additive and bounded", () => {
    expect(tacticalPushSchema.safeParse({}).success).toBe(true);
    expect(tacticalPushSchema.safeParse({ approvalResets: Array.from({ length: 201 }, () => reset) }).success).toBe(false);
    expect(tacticalPushSchema.safeParse({ approvalResets: [{ ...reset, agentId: "x" }] }).success).toBe(false);
    const hb = { version: "1", cache: { files: 0, bytes: 0 }, tactical: { reachable: true } };
    expect(heartbeatSchema.safeParse(hb).success).toBe(true); // older connectors
    expect(heartbeatSchema.safeParse({ ...hb, guard: { enabled: true, allowSetKnown: false, intervalSec: 30, resets: 0 } }).success).toBe(true);
  });
});

describe("guard reset activity", () => {
  it("says what was reset, where and when (UTC)", () => {
    const d = guardResetDraft(reset, "DESKTOP-Q6U5I2R", now);
    expect(d).toMatchObject({ source: "APPROVAL_GUARD", action: "winupdate_approve", agentHostname: "DESKTOP-Q6U5I2R", occurredAt: new Date("2026-10-16T10:42:17.123Z") });
    expect(d.message).toBe('Approval of KB5000001 on DESKTOP-Q6U5I2R reset automatically at 10:42:17 UTC (set outside PatchGate ("Cumulative Update"))');
    expect(describeActivity(d)).toContain("approved Windows updates on DESKTOP-Q6U5I2R");
    expect(d.dedupeKey).toBe(guardResetKey("agentAAAA1111", G1.toUpperCase(), new Date("2026-10-16T10:42:17.123Z")));
  });

  it("a failed reset is explicit; an unparsable or future time falls back to receipt time", () => {
    const d = guardResetDraft({ ...reset, kb: null, reset: false, error: "Tactical PUT -> 500", detectedAt: "garbage" }, null, now);
    expect(d.message).toMatch(new RegExp(`^Approval of ${G1} set outside PatchGate .*could NOT be reset automatically: Tactical PUT -> 500`));
    expect(d.occurredAt).toEqual(now);
  });

  it("audit drafts drop the service account's own work", () => {
    const ev = { id: 1, ts: "2026-10-16T10:00:00Z", actor: "patchgate-svc", action: "execute_script", objectType: "agent", agentHostname: null, agentId: null, message: null, ip: null };
    expect(auditDrafts([ev, { ...ev, id: 2, actor: "tacticaladmin" }], now).map((d) => d.tacticalId)).toEqual([2]);
  });
});
