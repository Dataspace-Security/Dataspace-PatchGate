/**
 * SYNC_AGENTS / SCAN / COLLECT results → endpoints, patch states, software inventory, discovery;
 * inventory schedules for connector-backed banks; the legacy direct path stands down.
 */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { TacticalClient } from "@/lib/tactical/client";
import { TENANT_A, TENANT_B, configureTestEnv, resetDb } from "./helpers";
import { enrollBody, makeConnectorKey, sessionUserOf } from "./connector-helpers";

const repoDir = mkdtempSync(join(tmpdir(), "pg-conn-inv-"));
configureTestEnv({ REPO_DIR: repoDir, LOG_LEVEL: "error" });
const { prisma } = await import("@/lib/db");
const { withTenant } = await import("@/lib/tenancy");
const { createEnrollmentCode } = await import("@/lib/connector/admin");
const { redeemEnrollment } = await import("@/lib/connector/enroll");
const { enqueueJob, claimJobs } = await import("@/lib/connector/queue");
const { acceptResult, processJobResult } = await import("@/lib/connector/results");
const { scheduleConnectorInventory, rebuildConnectorDiscovery } = await import("@/lib/scan/connector-schedule");
const { ingestDueEndpoints } = await import("@/lib/scan/ingest");

beforeEach(() => resetDb(prisma));
afterAll(async () => {
  await prisma.$disconnect();
  rmSync(repoDir, { recursive: true, force: true });
});

async function connector(tenantId = TENANT_A, name = "HQ") {
  const admin = sessionUserOf(await prisma.user.upsert({ where: { upn: "admin@pg" }, update: {}, create: { upn: "admin@pg", name: "A", role: "ADMIN" } }));
  const { code } = await createEnrollmentCode(admin, { tenantId, name });
  const r = await redeemEnrollment(enrollBody(code, makeConnectorKey()));
  return { id: r.connectorId, tenantId, name, maxConcurrentInstalls: 50, bandwidthLimitMbps: null };
}
type Conn = Awaited<ReturnType<typeof connector>>;

/** Enqueue a job of `type`, deliver it, post `result`, apply it. */
async function roundTrip(c: Conn, type: "SYNC_AGENTS" | "COLLECT" | "SCAN", payload: never, result: unknown) {
  const job = await withTenant(c.tenantId, (tx) => enqueueJob(tx, { tenantId: c.tenantId, connectorId: c.id, type, payload, expiresAt: new Date(Date.now() + 3_600_000) }));
  await claimJobs(c.tenantId, c.id);
  await acceptResult(c, job.id, { ok: true, result });
  expect(await processJobResult(c.tenantId, job.id)).toBe("applied");
  return job.id;
}

const agent = (agentId: string, hostname: string) => ({ agentId, hostname, site: "HQ", client: "Bank", os: "Windows 11", goarch: "amd64", version: "2.10.0", online: true });

describe("SYNC_AGENTS", () => {
  it("creates, updates, moves between connectors and unassigns endpoints — never touching another bank's agent", async () => {
    const hq = await connector(TENANT_A, "HQ");
    const dr = await connector(TENANT_A, "DR");
    const bankB = await connector(TENANT_B, "HQ");
    // bank B already owns this agent id
    await prisma.endpoint.create({ data: { tenantId: TENANT_B, tacticalAgentId: "agentBANKB001", hostname: "B-PC", connectorId: bankB.id } });

    await roundTrip(hq, "SYNC_AGENTS", {} as never, { agents: [agent("agentAAAA0001", "PC1"), agent("agentAAAA0002", "PC2"), agent("agentBANKB001", "STEAL")] });
    let rows = await prisma.endpoint.findMany({ orderBy: { tacticalAgentId: "asc" } });
    expect(rows.map((r) => [r.tacticalAgentId, r.tenantId, r.connectorId, r.hostname])).toEqual([
      ["agentAAAA0001", TENANT_A, hq.id, "PC1"],
      ["agentAAAA0002", TENANT_A, hq.id, "PC2"],
      ["agentBANKB001", TENANT_B, bankB.id, "B-PC"], // untouched
    ]);
    const audit = await prisma.auditEvent.findFirstOrThrow({ where: { action: "connector.agents_synced" } });
    expect(audit).toMatchObject({ tenantId: TENANT_A, payload: { created: 2, conflicts: 1, conflictAgents: ["agentBANKB001"] } });

    // PC2 moved to the DR site; HQ's next sync no longer lists it, and PC1 got renamed
    await roundTrip(dr, "SYNC_AGENTS", {} as never, { agents: [agent("agentAAAA0002", "PC2")] });
    await roundTrip(hq, "SYNC_AGENTS", {} as never, { agents: [agent("agentAAAA0001", "PC1-NEW")] });
    rows = await prisma.endpoint.findMany({ where: { tenantId: TENANT_A }, orderBy: { tacticalAgentId: "asc" } });
    expect(rows.map((r) => [r.tacticalAgentId, r.connectorId, r.hostname])).toEqual([
      ["agentAAAA0001", hq.id, "PC1-NEW"],
      ["agentAAAA0002", dr.id, "PC2"],
    ]);
    // DR reports nothing anymore → PC2 is unassigned (no jobs for it), but an EMPTY list from a site with PCs is ignored
    await roundTrip(dr, "SYNC_AGENTS", {} as never, { agents: [] });
    expect((await prisma.endpoint.findFirstOrThrow({ where: { tacticalAgentId: "agentAAAA0002" } })).connectorId).toBe(dr.id);
    await roundTrip(dr, "SYNC_AGENTS", {} as never, { agents: [agent("agentAAAA0009", "PC9")] });
    expect((await prisma.endpoint.findFirstOrThrow({ where: { tacticalAgentId: "agentAAAA0002" } })).connectorId).toBeNull();
  });

  it("stores Tactical last_seen / boot_time in UTC and never a future boot time (PC clock ahead)", async () => {
    const hq = await connector(TENANT_A, "HQ");
    const now = Date.now();
    const lastSeen = new Date(now - 3 * 86_400_000);
    const booted = new Date(now - 5 * 3_600_000);
    await roundTrip(hq, "SYNC_AGENTS", {} as never, {
      agents: [
        // offline for 3 days: last seen must stay 3 days ago, not "now"
        { ...agent("agentTIME0001", "PC-OLD"), online: false, lastSeen: lastSeen.toISOString().replace("Z", "+00:00"), bootTime: booted.getTime() / 1000 },
        // the PC's clock is ~4 h ahead (Tactical shows "Boot Time: -14543 seconds ago")
        { ...agent("agentTIME0002", "PC-SKEW"), lastSeen: new Date(now - 30_000).toISOString(), bootTime: now / 1000 + 14_543 },
        // older connector: no times at all
        agent("agentTIME0003", "PC-LEGACY"),
      ],
    });
    const rows = await prisma.endpoint.findMany({ where: { tenantId: TENANT_A }, orderBy: { tacticalAgentId: "asc" } });
    expect(rows[0]!.lastSeenAt?.toISOString()).toBe(lastSeen.toISOString());
    expect(rows[0]!.bootedAt?.toISOString()).toBe(booted.toISOString());
    expect(rows[1]!.bootedAt).toBeNull();
    expect(Math.abs(rows[1]!.lastSeenAt!.getTime() - (now - 30_000))).toBeLessThan(1000);
    expect(rows[2]!.lastSeenAt).not.toBeNull();
    expect(rows[2]!.bootedAt).toBeNull();

    // A later sync (update path): an offline agent without last_seen keeps its previous last-seen time.
    await roundTrip(hq, "SYNC_AGENTS", {} as never, { agents: [{ ...agent("agentTIME0001", "PC-OLD"), online: false }, agent("agentTIME0002", "PC-SKEW"), agent("agentTIME0003", "PC-LEGACY")] });
    const again = await prisma.endpoint.findFirstOrThrow({ where: { tacticalAgentId: "agentTIME0001" } });
    expect(again.lastSeenAt?.toISOString()).toBe(lastSeen.toISOString());
  });
});

describe("SCAN + COLLECT", () => {
  it("ingests Windows updates, software and agent version from DATA; discovery is rebuilt", async () => {
    const c = await connector();
    const ep = await prisma.endpoint.create({ data: { tenantId: TENANT_A, tacticalAgentId: "agentCOLL0001", hostname: "PC1", connectorId: c.id } });
    await roundTrip(c, "SCAN", { agentIds: ["agentCOLL0001", "agentCOLL0002"] } as never, { requested: ["agentCOLL0001"], failed: [{ agentId: "agentCOLL0002", error: "offline" }] });
    expect((await prisma.endpoint.findUniqueOrThrow({ where: { id: ep.id } })).lastScanRequestedAt).not.toBeNull();

    await roundTrip(c, "COLLECT", { agentIds: ["agentCOLL0001"], updates: true, software: true, agent: true } as never, {
      agents: [
        {
          agentId: "agentCOLL0001",
          updates: [
            { id: 11, guid: "AAAAAAAA-0000-0000-0000-000000000001", kb: "KB1", title: "Cumulative", installed: false, action: "nothing", severity: "Critical" },
            { id: 12, guid: "aaaaaaaa-0000-0000-0000-000000000002", kb: "KB2", title: "Defender", installed: true, action: "nothing", severity: null },
          ],
          software: [{ name: "7-Zip 24.08 (x64)", version: "24.08", publisher: "Igor Pavlov" }],
          agent: { version: "2.11.0", goarch: "amd64" },
        },
        { agentId: "agentUNKNOWN1", error: "not ours" },
      ],
    });
    const states = await prisma.endpointPatchState.findMany({ where: { endpointId: ep.id }, include: { patch: true }, orderBy: { tacticalUpdatePk: "asc" } });
    expect(states.map((s) => [s.patch.externalId, s.patch.severity, s.status])).toEqual([
      ["aaaaaaaa-0000-0000-0000-000000000001", "CRITICAL", "NEEDED"],
      ["aaaaaaaa-0000-0000-0000-000000000002", "UNSPECIFIED", "INSTALLED"],
    ]);
    expect(await prisma.installedSoftware.count({ where: { endpointId: ep.id } })).toBe(1);
    expect(await prisma.endpoint.findUniqueOrThrow({ where: { id: ep.id } })).toMatchObject({ agentVersion: "2.11.0", goarch: "amd64", lastScanAt: expect.any(Date) });
    // stored result is compacted after it was applied
    const job = await prisma.connectorJob.findFirstOrThrow({ where: { type: "COLLECT" } });
    expect(job.result).toMatchObject({ ok: true, compacted: true, result: { agents: 2 } });

    expect(await rebuildConnectorDiscovery()).toBe(1);
    expect(await prisma.discoveredApp.count({ where: { tenantId: TENANT_A } })).toBe(1);
    expect(await rebuildConnectorDiscovery()).toBe(0); // nothing new since
  });
});

describe("inventory schedules", () => {
  it("SYNC hourly, SCAN + COLLECT in ≤200-agent batches, never twice while outstanding; offline connectors get nothing", async () => {
    const c = await connector();
    const off = await connector(TENANT_B, "Offline");
    await prisma.connector.update({ where: { id: off.id }, data: { lastSeenAt: new Date(Date.now() - 60 * 60_000) } });
    await prisma.endpoint.createMany({
      data: Array.from({ length: 250 }, (_, i) => ({ tenantId: TENANT_A, tacticalAgentId: `agentSCHD${String(i).padStart(4, "0")}`, hostname: `PC${i}`, connectorId: c.id })),
    });
    const first = await scheduleConnectorInventory();
    expect(first).toMatchObject({ sync: 1, scan: 2, collect: 2, wuScan: 0, skippedOffline: 1 });
    const collects = await prisma.connectorJob.findMany({ where: { type: "COLLECT" } });
    expect(collects.map((j) => (j.payload as { agentIds: string[] }).agentIds.length).sort()).toEqual([200, 50]);
    expect(await scheduleConnectorInventory()).toMatchObject({ sync: 0, scan: 0, collect: 0 });
    expect(await prisma.connectorJob.count({ where: { connectorId: off.id } })).toBe(0);
  });

  it("the direct Tactical path stands down once the legacy bank has a connector", async () => {
    await prisma.endpoint.create({ data: { tenantId: TENANT_A, tacticalAgentId: "agentLEGACY01", hostname: "PC" } });
    const tactical = { scanUpdates: vi.fn(), getUpdates: vi.fn(async () => []), getSoftware: vi.fn(async () => []), getAgent: vi.fn(async () => ({ version: "2.10.0" })) } as unknown as TacticalClient;
    await connector(TENANT_A);
    expect(await ingestDueEndpoints(tactical)).toMatchObject({ viaConnector: true, ingested: 0 });
    expect(tactical.scanUpdates).not.toHaveBeenCalled();
  });
});
