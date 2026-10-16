import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { executeJob, isReadOnlyJob, type ExecutorDeps } from "../src/jobs/executors.ts";
import { AUDIT_PAGE_SIZE, isOutOfBand, tacticalAuditSync } from "../src/jobs/tactical-audit.ts";
import { jobPayloadSchemas, resultSchemas, TACTICAL_SERVICE_USERNAME } from "../src/protocol.ts";
import { createTacticalClient, type TacticalClient } from "../src/tactical/client.ts";
import type { TacticalAuditLog } from "../src/tactical/types.ts";
import { silentLogger } from "../src/util/log.ts";
import { FakeTactical } from "./helpers/fake-tactical.ts";

const KEY = "TACTICAL-TEST-KEY-AUDIT";
const SVC = TACTICAL_SERVICE_USERNAME;

let tactical: FakeTactical;
let client: TacticalClient;

/** Entries shaped like Tactical 1.5.2 AuditLog rows (logs/models.py audit_* helpers, AuditLogSerializer). */
function log(id: number, over: Partial<TacticalAuditLog> = {}): TacticalAuditLog {
  return {
    id,
    username: "tacticaladmin",
    agent: null,
    agent_id: null,
    entry_time: `2026-10-16T10:${String(id % 60).padStart(2, "0")}:00.000000+00:00`,
    action: "login",
    object_type: "user",
    message: "tacticaladmin logged in successfully",
    ip_address: "10.0.0.5",
    ...over,
  } as TacticalAuditLog;
}

const scriptRun = (id: number, user: string) =>
  log(id, { username: user, action: "execute_script", object_type: "agent", agent: "DESKTOP-Q6U5I2R", agent_id: "agentAAAA1111", message: `${user} ran script: "Install 7zip" on DESKTOP-Q6U5I2R` });

beforeEach(async () => {
  tactical = new FakeTactical({ apiKey: KEY });
  await tactical.start();
  client = createTacticalClient({ baseUrl: tactical.url, apiKey: KEY, timeoutMs: 5000 });
});
afterEach(async () => tactical.stop());

describe("protocol: TACTICAL_AUDIT_SYNC", () => {
  it("payload is strict and bounded", () => {
    expect(jobPayloadSchemas.TACTICAL_AUDIT_SYNC.safeParse({ afterId: 0, limit: 500 }).success).toBe(true);
    expect(jobPayloadSchemas.TACTICAL_AUDIT_SYNC.safeParse({ afterId: -1, limit: 10 }).success).toBe(false);
    expect(jobPayloadSchemas.TACTICAL_AUDIT_SYNC.safeParse({ afterId: 0, limit: 501 }).success).toBe(false);
    expect(jobPayloadSchemas.TACTICAL_AUDIT_SYNC.safeParse({ afterId: 0, limit: 5, path: "/accounts/" }).success).toBe(false);
  });
  it("result caps the event list", () => {
    const ev = { id: 1, ts: "x", actor: "a", action: "login", objectType: "user", agentHostname: null, agentId: null, message: null, ip: null };
    expect(resultSchemas.TACTICAL_AUDIT_SYNC.safeParse({ events: [ev], cursor: 1, more: false }).success).toBe(true);
    expect(resultSchemas.TACTICAL_AUDIT_SYNC.safeParse({ events: Array.from({ length: 501 }, (_, i) => ({ ...ev, id: i + 1 })), cursor: 1, more: true }).success).toBe(false);
  });
  it("is a read-only job (never journalled, safe to re-run)", () => {
    expect(isReadOnlyJob("TACTICAL_AUDIT_SYNC")).toBe(true);
  });
});

describe("service-account filter", () => {
  it("drops the service account's own API actions but reports logins as it", () => {
    expect(isOutOfBand({ username: SVC, action: "execute_script" })).toBe(false);
    expect(isOutOfBand({ username: SVC, action: "modify" })).toBe(false);
    expect(isOutOfBand({ username: SVC, action: "login" })).toBe(true);
    expect(isOutOfBand({ username: SVC, action: "failed_login" })).toBe(true);
    expect(isOutOfBand({ username: "tacticaladmin", action: "execute_script" })).toBe(true);
  });
});

describe("tacticalAuditSync", () => {
  it("reports human actions after the cursor, oldest first, and advances the cursor past service entries", async () => {
    tactical.auditLogs.push(
      log(1),
      scriptRun(2, SVC), // PatchGate's own install script run
      log(3, { action: "modify", object_type: "winupdatepolicy", message: "tacticaladmin modified winupdatepolicy Default" }),
      log(4, { action: "execute_command", object_type: "agent", agent: "DESKTOP-Q6U5I2R", agent_id: "agentAAAA1111", message: "tacticaladmin issued powershell command on DESKTOP-Q6U5I2R." }),
      log(5, { username: "site-root (break-glass)", action: "modify", object_type: "user", message: "BREAK-GLASS ON: dashboard login of tacticaladmin unblocked" }),
      scriptRun(6, SVC),
    );
    const r = await tacticalAuditSync(client, { afterId: 1, limit: 500 });
    expect(r.events.map((e) => e.id)).toEqual([3, 4, 5]);
    expect(r.cursor).toBe(6);
    expect(r.more).toBe(false);
    expect(r.reset).toBeUndefined();
    expect(r.events[1]).toMatchObject({ actor: "tacticaladmin", action: "execute_command", objectType: "agent", agentHostname: "DESKTOP-Q6U5I2R", agentId: "agentAAAA1111", ip: "10.0.0.5" });
    // read-only: a single PATCH to the audit view, newest first
    expect(tactical.calls.map((c) => `${c.method} ${c.path}`)).toEqual(["PATCH /logs/audit/"]);
    expect(tactical.calls[0]!.body).toEqual({ pagination: { sortBy: "id", descending: true, page: 1, rowsPerPage: AUDIT_PAGE_SIZE } });
  });

  it("pages back until the cursor and de-duplicates entries that shift between pages", async () => {
    for (let i = 1; i <= 450; i++) tactical.auditLogs.push(i % 2 ? log(i) : scriptRun(i, SVC));
    const r = await tacticalAuditSync(client, { afterId: 100, limit: 500 });
    expect(r.events).toHaveLength(175); // odd ids 101..449
    expect(new Set(r.events.map((e) => e.id)).size).toBe(175);
    expect(r.events[0]!.id).toBe(101);
    expect(r.cursor).toBe(450);
    expect(tactical.calls.length).toBe(2); // 450..251, 250..51 (reaches the cursor)
  });

  it("returns at most `limit` events and flags more (next page queued by PatchGate)", async () => {
    for (let i = 1; i <= 30; i++) tactical.auditLogs.push(log(i));
    const first = await tacticalAuditSync(client, { afterId: 0, limit: 10 });
    expect(first.events.map((e) => e.id)).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    expect(first).toMatchObject({ cursor: 10, more: true });
    const second = await tacticalAuditSync(client, { afterId: first.cursor, limit: 10 });
    expect(second.events[0]!.id).toBe(11);
    const last = await tacticalAuditSync(client, { afterId: 20, limit: 10 });
    expect(last).toMatchObject({ cursor: 30, more: false });
  });

  it("nothing new: empty result, cursor unchanged", async () => {
    tactical.auditLogs.push(log(1), scriptRun(2, SVC));
    expect(await tacticalAuditSync(client, { afterId: 2, limit: 500 })).toEqual({ events: [], cursor: 2, more: false });
    tactical.auditLogs.length = 0;
    expect(await tacticalAuditSync(client, { afterId: 0, limit: 500 })).toEqual({ events: [], cursor: 0, more: false });
  });

  it("flags a reset when Tactical's newest id is below the cursor (log purged / Tactical reinstalled)", async () => {
    tactical.auditLogs.push(log(1), log(2));
    const r = await tacticalAuditSync(client, { afterId: 900, limit: 500 });
    expect(r.reset).toBe(true);
    expect(r.events.map((e) => e.id)).toEqual([1, 2]);
    expect(r.cursor).toBe(2);
  });

  it("flags agent auto-update being turned on (CoreSettings change) and never forwards the snapshots", async () => {
    tactical.auditLogs.push(
      log(8, {
        action: "modify",
        object_type: "coresettings",
        message: "tacticaladmin modified coresettings Global Site Settings",
        before_value: { agent_auto_update: false, smtp_password: "secret-before" },
        after_value: { agent_auto_update: true, smtp_password: "secret-after" },
      } as Partial<TacticalAuditLog>),
      log(9, { action: "modify", object_type: "coresettings", before_value: { agent_auto_update: false }, after_value: { agent_auto_update: false } } as Partial<TacticalAuditLog>),
    );
    const r = await tacticalAuditSync(client, { afterId: 0, limit: 500 });
    expect(r.events[0]!.message).toMatch(/^AGENT AUTO-UPDATE TURNED ON/);
    expect(r.events[1]!.message).not.toMatch(/AUTO-UPDATE/);
    expect(JSON.stringify(r)).not.toContain("secret-");
  });

  it("runs through executeJob with a schema-valid result", async () => {
    tactical.auditLogs.push(log(7, { message: "x".repeat(400) }));
    const deps = { tactical: client, log: silentLogger } as unknown as ExecutorDeps;
    const r = (await executeJob("TACTICAL_AUDIT_SYNC", { afterId: 0, limit: 500 }, deps)) as { events: unknown[] };
    expect(resultSchemas.TACTICAL_AUDIT_SYNC.safeParse(r).success).toBe(true);
    expect(r.events).toHaveLength(1);
  });

  it("fails when Tactical denies the audit view (missing can_view_auditlogs)", async () => {
    const denied = createTacticalClient({ baseUrl: tactical.url, apiKey: "wrong", timeoutMs: 5000 });
    await expect(executeJob("TACTICAL_AUDIT_SYNC", { afterId: 0, limit: 5 }, { tactical: denied, log: silentLogger } as unknown as ExecutorDeps)).rejects.toThrow(/401/);
  });
});
