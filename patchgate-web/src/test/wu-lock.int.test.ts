/**
 * Windows Update lock — DB integration (TEST_DATABASE_URL=…/patchgate_test_conn): the WU_SCAN result's wuLock
 * report is stored per endpoint; locked → NOT locked writes endpoint.wu_lock_broken on the bank's audit chain
 * and ONE WU_LOCK_BROKEN notification per scan result; staying unlocked does not alert again; locking again
 * writes endpoint.wu_lock_restored.
 */
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { TENANT_A, TENANT_B, configureTestEnv, resetDb } from "./helpers";

configureTestEnv();

const { prisma } = await import("@/lib/db");
const { withTenant } = await import("@/lib/tenancy");
const { verifyAuditLog } = await import("@/lib/audit/service");
const { resultSchemas } = await import("@/lib/connector/protocol");
const hooks = await import("@/lib/winupdate/hooks");

let connectorId = "";
let job = 0;

beforeEach(async () => {
  await resetDb(prisma);
  connectorId = (await prisma.connector.create({ data: { tenantId: TENANT_A, name: "HO", publicKey: "k".repeat(43) + "=" } })).id;
  for (const [agent, host] of [["agent-a-0001", "pc-a1"], ["agent-a-0002", "pc-a2"]] as const) {
    await prisma.endpoint.create({ data: { tenantId: TENANT_A, tacticalAgentId: agent, hostname: host, connectorId } });
  }
  await prisma.endpoint.create({ data: { tenantId: TENANT_B, tacticalAgentId: "agent-b-0001", hostname: "pc-b1" } });
  await prisma.user.create({ data: { upn: "admin@a.example", name: "Bank admin", role: "ADMIN", tenantId: TENANT_A } });
});

afterAll(async () => {
  await prisma.$disconnect();
});

type Lock = { locked: boolean; issues: string[]; lastOutsideInstall?: { at: string; title: string } | null };
function scan(locks: Record<string, Lock | undefined>, failed: string[] = []) {
  return resultSchemas.WU_SCAN.parse({
    agents: Object.entries(locks).map(([agentId, wuLock]) =>
      failed.includes(agentId) ? { agentId, error: "scan failed on PC: x", ...(wuLock ? { wuLock } : {}) } : { agentId, updates: [], ...(wuLock ? { wuLock } : {}) },
    ),
  });
}
const ingest = (result: ReturnType<typeof scan>) =>
  withTenant(TENANT_A, (tx) => hooks.handleWuScanResult(tx, { tenantId: TENANT_A, connectorId, jobId: `job-${++job}` }, result));
const ep = (agent: string) => prisma.endpoint.findUniqueOrThrow({ where: { tacticalAgentId: agent } });
const audits = (action: string) => prisma.auditEvent.findMany({ where: { tenantId: TENANT_A, action }, orderBy: { seq: "asc" } });
const lockNotes = () => prisma.notification.findMany({ where: { event: "WU_LOCK_BROKEN" } });

const LOCKED: Lock = { locked: true, issues: [] };
const OPEN: Lock = { locked: false, issues: ["WindowsUpdate\\AU\\NoAutoUpdate is 0 (must be 1)"], lastOutsideInstall: { at: "2026-10-01T10:00:00Z", title: "2026-09 Cumulative Update" } };

describe("Windows Update lock state from WU_SCAN", () => {
  it("stores the state; locked → NOT locked audits + notifies once; restored audits; old results without wuLock change nothing", async () => {
    await ingest(scan({ "agent-a-0001": LOCKED, "agent-a-0002": undefined }));
    expect(await ep("agent-a-0001")).toMatchObject({ wuLocked: true, wuLockDetail: { issues: [], lastOutsideInstall: null } });
    expect((await ep("agent-a-0001")).wuLockCheckedAt).toBeInstanceOf(Date);
    expect((await ep("agent-a-0002")).wuLocked).toBeNull(); // older scan script: no report
    expect(await audits("endpoint.wu_lock_broken")).toHaveLength(0);
    expect(await lockNotes()).toHaveLength(0);

    // locked → NOT locked (also reported by a scan that failed); a first report of an unlocked PC alerts too
    await ingest(scan({ "agent-a-0001": OPEN, "agent-a-0002": OPEN }, ["agent-a-0001"]));
    const a1 = await ep("agent-a-0001");
    expect(a1).toMatchObject({ wuLocked: false, wuLockDetail: { issues: OPEN.issues, lastOutsideInstall: OPEN.lastOutsideInstall } });
    const broken = await audits("endpoint.wu_lock_broken");
    expect(broken.map((e) => e.entityId).sort()).toEqual([a1.id, (await ep("agent-a-0002")).id].sort());
    expect(broken.find((e) => e.entityId === a1.id)!.payload).toMatchObject({ hostname: "pc-a1", previous: true, issues: OPEN.issues });
    const notes = await lockNotes();
    expect(notes.length).toBeGreaterThan(0);
    expect(new Set(notes.map((n) => n.tenantId))).toEqual(new Set([TENANT_A]));
    expect(notes[0]!.subject).toContain("NOT locked on 2 PCs");
    expect(notes[0]!.bodyText).toContain("pc-a1");
    expect(notes[0]!.bodyText).toContain("NoAutoUpdate");

    // still NOT locked: no new alert
    await ingest(scan({ "agent-a-0001": OPEN }));
    expect(await audits("endpoint.wu_lock_broken")).toHaveLength(2);
    expect(await lockNotes()).toHaveLength(notes.length);

    // locked again
    await ingest(scan({ "agent-a-0001": LOCKED }));
    expect((await ep("agent-a-0001")).wuLocked).toBe(true);
    expect(await audits("endpoint.wu_lock_restored")).toHaveLength(1);
    expect(await lockNotes()).toHaveLength(notes.length);

    // a report without wuLock keeps the last known state
    await ingest(scan({ "agent-a-0001": undefined }));
    expect((await ep("agent-a-0001")).wuLocked).toBe(true);

    expect((await verifyAuditLog(TENANT_A)).valid).toBe(true);
  });

  it("ignores lock reports about another bank's PC", async () => {
    await ingest(scan({ "agent-b-0001": OPEN }));
    expect((await ep("agent-b-0001")).wuLocked).toBeNull();
    expect(await lockNotes()).toHaveLength(0);
  });
});
