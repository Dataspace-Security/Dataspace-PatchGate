/**
 * Real-time Tactical guard (connector protocol §8): signed POST /tactical-events pushes (auth, signature, replay),
 * ingestion (TacticalActivity once per item, bank-chain audit, cursor), coalesced TACTICAL_OUT_OF_BAND alerts,
 * row-level security, the signed TACTICAL_GUARD_SYNC allow-set baseline after a connector start, and the
 * COLLECT re-check fallback that is skipped for connectors with an armed guard.
 */
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { TENANT_A, TENANT_B, configureTestEnv, resetDb } from "./helpers";
import { enrollBody, makeConnectorKey, sessionUserOf, signedParts, type ConnectorKey } from "./connector-helpers";

configureTestEnv({ LOG_LEVEL: "error", AGENT_SYNC_MINUTES: "15" });
const { prisma } = await import("@/lib/db");
const { withTenant } = await import("@/lib/tenancy");
const { createEnrollmentCode } = await import("@/lib/connector/admin");
const { redeemEnrollment } = await import("@/lib/connector/enroll");
const { authenticateConnector } = await import("@/lib/connector/auth");
const { ConnectorApiError, ConnectorAuthError } = await import("@/lib/connector/errors");
const { enqueueJob, claimJobs } = await import("@/lib/connector/queue");
const { ingestTacticalPush } = await import("@/lib/connector/tactical-push");
const { requestGuardSyncIfNeeded, buildAllowEntries } = await import("@/lib/connector/guard-sync");
const { listTacticalActivity, NOTIFY_COALESCE_MS } = await import("@/lib/connector/tactical-activity");
const { scheduleConnectorInventory } = await import("@/lib/scan/connector-schedule");
const { API_PREFIX, jobPayloadSchemas, verifyJob } = await import("@/lib/connector/protocol");
const { jobSigningPublicKey } = await import("@/lib/connector/keys");

beforeEach(() => resetDb(prisma));
afterAll(async () => prisma.$disconnect());

const PUSH_PATH = `${API_PREFIX}/tactical-events`;
const AGENT = "agentAAAA1111";
const G = (n: number) => `${String(n).padStart(8, "0")}-0000-4000-8000-000000000000`;

async function mkUser(upn: string, role: "ADMIN" | "AUDITOR", tenantId: string | null) {
  return sessionUserOf(await prisma.user.create({ data: { upn, name: upn, role, tenantId } }));
}

async function connector(tenantId = TENANT_A, name = "HQ") {
  const admin = sessionUserOf(await prisma.user.upsert({ where: { upn: "enrol@pg.example" }, update: {}, create: { upn: "enrol@pg.example", name: "E", role: "ADMIN" } }));
  const { code } = await createEnrollmentCode(admin, { tenantId, name });
  const key = makeConnectorKey();
  const r = await redeemEnrollment(enrollBody(code, key));
  await prisma.connector.update({ where: { id: r.connectorId }, data: { lastSeenAt: new Date() } });
  return { id: r.connectorId, tenantId, name, key, maxConcurrentInstalls: 50, bandwidthLimitMbps: null };
}
type Conn = Awaited<ReturnType<typeof connector>>;

/** Exactly what the connector does: sign the body, PatchGate authenticates the request, then ingests it. */
async function push(c: Conn, body: unknown, key: ConnectorKey = c.key, nonce?: string) {
  const text = JSON.stringify(body);
  const authed = await authenticateConnector(signedParts(key, c.id, "POST", PUSH_PATH, text, nonce ? { nonce } : {}));
  return ingestTacticalPush(authed, JSON.parse(text));
}

const ev = (id: number, over: Record<string, unknown> = {}) => ({
  id,
  ts: `2026-10-16T10:${String(id).padStart(2, "0")}:00+00:00`,
  actor: "tacticaladmin",
  action: "login",
  objectType: "user",
  agentHostname: null,
  agentId: null,
  message: "tacticaladmin logged in successfully",
  ip: "10.0.0.5",
  ...over,
});

const reset = (n: number, over: Record<string, unknown> = {}) => ({
  agentId: AGENT,
  hostname: "PC-FROM-TACTICAL",
  guid: G(n),
  kb: `KB${5000000 + n}`,
  title: `2026-10 Update ${n}`,
  detectedAt: "2026-10-16T10:42:17.000Z",
  reset: true,
  error: null,
  ...over,
});

async function endpoint(c: Conn, agentId = AGENT, hostname = "DESKTOP-Q6U5I2R") {
  return prisma.endpoint.create({ data: { tenantId: c.tenantId, connectorId: c.id, tacticalAgentId: agentId, hostname } });
}

describe("POST /tactical-events: authentication", () => {
  it("accepts a signed push; refuses a bad signature and a replayed nonce", async () => {
    const c = await connector();
    expect(await push(c, { audit: { afterId: 0, events: [ev(1)], cursor: 1 } }, c.key, "nonce-guard-0000000001")).toEqual({ auditCursor: 1, stored: 1 });
    await expect(push(c, { audit: { afterId: 1, events: [ev(2)], cursor: 2 } }, c.key, "nonce-guard-0000000001")).rejects.toThrow(ConnectorAuthError); // replay
    await expect(push(c, { audit: { afterId: 1, events: [ev(2)], cursor: 2 } }, makeConnectorKey())).rejects.toThrow(ConnectorAuthError); // not its key
    expect(await prisma.tacticalActivity.count()).toBe(1);
  });

  it("rejects an invalid or oversized body as 400 (the connector drops it, never loops)", async () => {
    const c = await connector();
    const authed = await authenticateConnector(signedParts(c.key, c.id, "POST", PUSH_PATH, "{}"));
    await expect(ingestTacticalPush(authed, { approvalResets: [reset(1, { agentId: "../../etc" })] })).rejects.toThrow(ConnectorApiError);
    await expect(ingestTacticalPush(authed, { audit: { afterId: 0, events: Array.from({ length: 201 }, (_, i) => ev(i + 1)), cursor: 201 } })).rejects.toThrow(/invalid tactical-events/);
    await expect(ingestTacticalPush(authed, { unknown: true })).rejects.toThrow(ConnectorApiError);
  });
});

describe("ingestion", () => {
  it("stores audit entries and guard resets once, audits them on the bank chain, advances the cursor, alerts once", async () => {
    await mkUser("admin@a.example", "ADMIN", TENANT_A);
    const c = await connector();
    await endpoint(c);
    const body = {
      audit: { afterId: 0, events: [ev(3), ev(4, { actor: "patchgate-svc", action: "execute_script", objectType: "agent" })], cursor: 7 },
      approvalResets: [reset(1), reset(2, { reset: false, error: "Tactical PUT /winupdate/1/ -> 500" })],
    };
    expect(await push(c, body)).toEqual({ auditCursor: 7, stored: 3 });
    const rows = await prisma.tacticalActivity.findMany({ orderBy: [{ source: "asc" }, { message: "asc" }] });
    expect(rows.map((r) => [r.tenantId, r.source, r.agentHostname])).toEqual([
      [TENANT_A, "APPROVAL_GUARD", "DESKTOP-Q6U5I2R"],
      [TENANT_A, "APPROVAL_GUARD", "DESKTOP-Q6U5I2R"],
      [TENANT_A, "AUDIT_LOG", null],
    ]);
    expect(rows[0]!.message).toBe('Approval of KB5000001 on DESKTOP-Q6U5I2R reset automatically at 10:42:17 UTC (set outside PatchGate ("2026-10 Update 1"))');
    expect(rows[1]!.message).toMatch(/KB5000002 on DESKTOP-Q6U5I2R .*could NOT be reset automatically: Tactical PUT/);
    expect(rows[0]!.occurredAt.toISOString()).toBe("2026-10-16T10:42:17.000Z");
    expect((await prisma.connector.findUniqueOrThrow({ where: { id: c.id } })).tacticalAuditCursor).toBe(7);
    expect(await prisma.auditEvent.count({ where: { action: "tactical.out_of_band_action", tenantId: TENANT_A } })).toBe(3);
    const mails = await prisma.notification.findMany({ where: { event: "TACTICAL_OUT_OF_BAND", channel: "EMAIL" } });
    expect(mails.map((m) => m.target).sort()).toEqual(["admin@a.example", "enrol@pg.example"]);
    expect(mails[0]!.severity).toBe("critical");

    // the connector re-sends the batch (its first answer was lost): nothing new, cursor never moves back
    expect(await push(c, { ...body, audit: { ...body.audit, cursor: 5 } })).toEqual({ auditCursor: 7, stored: 0 });
    expect(await prisma.tacticalActivity.count()).toBe(3);
    expect(await prisma.notification.count({ where: { event: "TACTICAL_OUT_OF_BAND" } })).toBe(2);
  });

  it("a purged Tactical log (reset) records an audit-log gap and takes the connector's cursor", async () => {
    const c = await connector();
    await prisma.connector.update({ where: { id: c.id }, data: { tacticalAuditCursor: 90 } });
    expect(await push(c, { audit: { afterId: 90, events: [ev(1)], cursor: 1, reset: true } })).toEqual({ auditCursor: 1, stored: 2 });
    expect((await prisma.tacticalActivity.findMany()).map((r) => r.source).sort()).toEqual(["AUDIT_LOG", "AUDIT_RESET"]);
  });

  it("coalesces a burst into one alert; the next alert after the window counts what was coalesced", async () => {
    await mkUser("admin@a.example", "ADMIN", TENANT_A);
    const c = await connector();
    await push(c, { audit: { afterId: 0, events: [ev(1)], cursor: 1 } });
    await push(c, { audit: { afterId: 1, events: [ev(2)], cursor: 2 } });
    await push(c, { audit: { afterId: 2, events: [ev(3), ev(4)], cursor: 4 } });
    expect(await prisma.tacticalActivity.count()).toBe(4); // all stored + audited at once
    expect(await prisma.auditEvent.count({ where: { action: "tactical.out_of_band_action" } })).toBe(4);
    const mails = () => prisma.notification.findMany({ where: { event: "TACTICAL_OUT_OF_BAND", channel: "EMAIL", target: "admin@a.example" }, orderBy: { createdAt: "asc" } });
    expect(await mails()).toHaveLength(1);
    // the window passes
    const back = (NOTIFY_COALESCE_MS + 60_000) / 1000;
    await prisma.$executeRaw`UPDATE "Notification" SET "createdAt" = "createdAt" - make_interval(secs => ${back})`;
    await prisma.$executeRaw`UPDATE "TacticalActivity" SET "receivedAt" = "receivedAt" - make_interval(secs => ${back})`;
    await push(c, { audit: { afterId: 4, events: [ev(5)], cursor: 5 } });
    const after = await mails();
    expect(after).toHaveLength(2);
    expect(after[1]!.subject).toContain("4 action(s)"); // 3 coalesced + 1 new
  });

  it("row-level security: a bank's push only ever writes and shows that bank's rows", async () => {
    const a = await connector(TENANT_A, "HQ-A");
    const b = await connector(TENANT_B, "HQ-B");
    const B_AGENT = "agentBANKB0001";
    await endpoint(b, B_AGENT, "BANK-B-PC");
    await push(a, { approvalResets: [reset(1, { agentId: B_AGENT })] }); // bank A's connector names bank B's PC
    const rows = await prisma.tacticalActivity.findMany();
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ tenantId: TENANT_A, connectorId: a.id, agentHostname: "PC-FROM-TACTICAL" }); // never bank B's name
    expect((await listTacticalActivity({ kind: "tenant", tenantId: TENANT_B })).rows).toEqual([]);
    expect((await listTacticalActivity({ kind: "tenant", tenantId: TENANT_A })).rows).toHaveLength(1);
    expect(await withTenant(TENANT_B, (tx) => tx.tacticalActivity.count())).toBe(0);
  });
});

describe("TACTICAL_GUARD_SYNC (allow-set baseline after a connector start)", () => {
  it("merges DEPLOY_WINDOWS approvals per PC (union of guids, latest window end)", () => {
    const t = (h: number) => new Date(Date.UTC(2026, 9, 16, h));
    expect(
      buildAllowEntries([
        { payload: { agentId: AGENT, guids: [G(1).toUpperCase()] }, expiresAt: t(10) },
        { payload: { agentId: AGENT, guids: [G(2)] }, expiresAt: t(12) },
        { payload: { agentId: "agentBBBB2222", guids: [G(3)] }, expiresAt: t(11) },
        { payload: null, expiresAt: t(13) },
      ]),
    ).toEqual([
      { agentId: AGENT, guids: [G(1), G(2)], until: t(12).toISOString() },
      { agentId: "agentBBBB2222", guids: [G(3)], until: t(11).toISOString() },
    ]);
  });

  it("is signed and queued once when the heartbeat reports an unknown allow-set, with PatchGate's audit cursor", async () => {
    const c = await connector();
    await prisma.connector.update({ where: { id: c.id }, data: { tacticalAuditCursor: 42 } });
    const until = new Date(Date.now() + 3_600_000);
    await withTenant(c.tenantId, (tx) =>
      enqueueJob(tx, { tenantId: c.tenantId, connectorId: c.id, type: "DEPLOY_WINDOWS", payload: { agentId: AGENT, guids: [G(1)], rebootPolicy: "NEVER" }, expiresAt: until }),
    );
    expect(await requestGuardSyncIfNeeded(c, { enabled: true, allowSetKnown: true })).toBe(0);
    expect(await requestGuardSyncIfNeeded(c, { enabled: false, allowSetKnown: false })).toBe(0);
    expect(await requestGuardSyncIfNeeded(c, undefined)).toBe(0); // older connector: no guard
    expect(await requestGuardSyncIfNeeded(c, { enabled: true, allowSetKnown: false })).toBe(1);
    expect(await requestGuardSyncIfNeeded(c, { enabled: true, allowSetKnown: false })).toBe(0); // outstanding
    const jobs = await claimJobs(c.tenantId, c.id);
    const sync = jobs.find((j) => j.type === "TACTICAL_GUARD_SYNC")!;
    expect(sync.payload).toMatchObject({ part: 1, parts: 1, auditCursor: 42, allow: [{ agentId: AGENT, guids: [G(1)], until: until.toISOString() }] });
    expect(jobPayloadSchemas.TACTICAL_GUARD_SYNC.safeParse(sync.payload).success).toBe(true);
    expect(verifyJob(sync, await jobSigningPublicKey(c.tenantId), c.id, Date.now())).toMatchObject({ ok: true, type: "TACTICAL_GUARD_SYNC" });
  });
});

describe("COLLECT re-check fallback", () => {
  it("runs after human activity only for connectors without an armed real-time guard", async () => {
    const c = await connector();
    await endpoint(c);
    await prisma.connector.update({ where: { id: c.id }, data: { tacticalHumanSeenAt: new Date() } });
    const guardHb = (allowSetKnown: boolean) => ({ version: "1", cache: { files: 0, bytes: 0 }, tactical: { reachable: true }, guard: { enabled: true, allowSetKnown, intervalSec: 30, resets: 0 } });
    await prisma.connector.update({ where: { id: c.id }, data: { heartbeat: guardHb(true) } });
    expect((await scheduleConnectorInventory()).approvalCheck).toBe(0);
    await prisma.connector.update({ where: { id: c.id }, data: { heartbeat: guardHb(false) } }); // guard not armed yet
    expect((await scheduleConnectorInventory()).approvalCheck).toBe(1);
  });
});
