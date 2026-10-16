import { describe, expect, it } from "vitest";
import { agentTimes, formatAgo, normaliseAgentTime, parseTacticalTime } from "./agent-times";

const NOW = new Date("2026-10-16T12:00:00.000Z");
const epoch = (iso: string) => new Date(iso).getTime() / 1000;

/** Tactical-shaped rows of GET /agents/ (AgentTableSerializer fields used by PatchGate). */
const tacticalAgents = {
  healthy: { agent_id: "AgentHealthy01", hostname: "BR01-PC01", status: "online", last_seen: "2026-10-16T11:59:30.123456Z", boot_time: epoch("2026-10-16T08:00:00Z") },
  offlineWeek: { agent_id: "AgentOffline01", hostname: "BR01-PC02", status: "offline", last_seen: "2026-10-09T12:00:00+05:30", boot_time: epoch("2026-10-01T09:00:00Z") },
  // The PC clock runs about 4 h ahead: Tactical itself shows "Boot Time: -14543 seconds ago".
  clockAhead: { agent_id: "AgentSkewed001", hostname: "BR02-PC07", status: "online", last_seen: "2026-10-16T11:58:00Z", boot_time: NOW.getTime() / 1000 + 14543 },
  noZone: { agent_id: "AgentNoZone001", hostname: "BR03-PC01", status: "online", last_seen: "2026-10-16 10:00:00", boot_time: String(epoch("2026-10-15T23:00:00Z")) },
  garbage: { agent_id: "AgentGarbage01", hostname: "BR03-PC02", status: "overdue", last_seen: "yesterday", boot_time: 0 },
};

function fromTactical(a: { status?: string; last_seen?: unknown; boot_time?: unknown }) {
  return agentTimes({ lastSeen: a.last_seen, bootTime: a.boot_time, online: a.status ? a.status === "online" : null }, NOW);
}

describe("Tactical agent times", () => {
  it("healthy agent: last_seen (ISO, microseconds, Z) and boot_time (epoch seconds) in UTC", () => {
    const t = fromTactical(tacticalAgents.healthy);
    expect(t.lastSeenAt?.toISOString()).toBe("2026-10-16T11:59:30.123Z");
    expect(t.bootedAt?.toISOString()).toBe("2026-10-16T08:00:00.000Z");
    expect(formatAgo(t.lastSeenAt, NOW)).toBe("just now");
    expect(formatAgo(t.bootedAt, NOW)).toBe("4 h ago");
  });

  it("offline agent keeps Tactical's real last contact (offset converted to UTC), not the sync time", () => {
    const t = fromTactical(tacticalAgents.offlineWeek);
    expect(t.lastSeenAt?.toISOString()).toBe("2026-10-09T06:30:00.000Z");
    expect(formatAgo(t.lastSeenAt, NOW)).toBe("7 days ago");
  });

  it("boot time in the future (PC clock ahead) is unknown, never a negative duration", () => {
    const t = fromTactical(tacticalAgents.clockAhead);
    expect(t.bootedAt).toBeNull();
    expect(formatAgo(t.bootedAt, NOW)).toBe("unknown");
    expect(t.lastSeenAt?.toISOString()).toBe("2026-10-16T11:58:00.000Z");
  });

  it("small skew is clamped to now (just now)", () => {
    const d = normaliseAgentTime(NOW.getTime() / 1000 + 120, NOW, 10 * 60_000);
    expect(d?.toISOString()).toBe(NOW.toISOString());
    expect(formatAgo(new Date(NOW.getTime() + 30_000), NOW)).toBe("just now");
  });

  it("a time without offset is UTC, numeric strings are epoch seconds", () => {
    const t = fromTactical(tacticalAgents.noZone);
    expect(t.lastSeenAt?.toISOString()).toBe("2026-10-16T10:00:00.000Z");
    expect(t.bootedAt?.toISOString()).toBe("2026-10-15T23:00:00.000Z");
  });

  it("garbage: unknown boot time; an agent not online without usable last_seen keeps its previous value", () => {
    const t = fromTactical(tacticalAgents.garbage);
    expect(t.bootedAt).toBeNull();
    expect(t.lastSeenAt).toBeNull();
  });

  it("older connectors (no last_seen at all, online or unknown): seen at sync time", () => {
    expect(agentTimes({ online: true }, NOW).lastSeenAt?.toISOString()).toBe(NOW.toISOString());
    expect(agentTimes({}, NOW).lastSeenAt?.toISOString()).toBe(NOW.toISOString());
  });

  it("parser edge cases", () => {
    expect(parseTacticalTime(1_760_000_000_000)?.toISOString()).toBe(new Date(1_760_000_000_000).toISOString()); // ms
    expect(parseTacticalTime("1999-12-31T00:00:00Z")?.getUTCFullYear()).toBe(1999);
    expect(normaliseAgentTime("1999-12-31T00:00:00Z", NOW, 0)).toBeNull(); // implausibly old
    expect(normaliseAgentTime("2030-01-01T00:00:00Z", NOW, 24 * 3_600_000)).toBeNull(); // far future
    expect(parseTacticalTime(Number.NaN)).toBeNull();
    expect(parseTacticalTime(-5)).toBeNull();
    expect(parseTacticalTime({})).toBeNull();
    expect(parseTacticalTime("")).toBeNull();
  });

  it("formatAgo ranges", () => {
    expect(formatAgo(null, NOW)).toBe("unknown");
    expect(formatAgo(new Date(NOW.getTime() - 5 * 60_000), NOW)).toBe("5 min ago");
    expect(formatAgo(new Date(NOW.getTime() - 47 * 3_600_000), NOW)).toBe("47 h ago");
    expect(formatAgo(new Date(NOW.getTime() - 3 * 86_400_000), NOW)).toBe("3 days ago");
  });
});
