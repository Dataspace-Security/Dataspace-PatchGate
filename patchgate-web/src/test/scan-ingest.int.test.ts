import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { TacticalClient } from "@/lib/tactical/client";
import type { TacticalWinUpdate } from "@/lib/tactical/types";
import { TENANT_A, TENANT_B, configureTestEnv, resetDb } from "./helpers";

configureTestEnv();
const { prisma } = await import("@/lib/db");
const { ingestDueEndpoints } = await import("@/lib/scan/ingest");

function tactical(updates: TacticalWinUpdate[], software: { name: string; version: string }[] = []): TacticalClient {
  return {
    listAgents: vi.fn(async () => []),
    getAgent: vi.fn(async () => ({ version: "2.11.0", goarch: "amd64" })),
    scanUpdates: vi.fn(async () => {}),
    getUpdates: vi.fn(async () => updates),
    setUpdateAction: vi.fn(async () => {}),
    installApproved: vi.fn(async () => {}),
    getSoftware: vi.fn(async () => software),
    refreshSoftware: vi.fn(async () => {}),
    runScript: vi.fn(async () => ""),
  };
}

const upd = (id: number, guid: string, installed: boolean, severity = "Critical"): TacticalWinUpdate => ({
  id, guid, kb: `KB${id}`, title: `Update ${id}`, installed, action: "nothing", severity,
});

beforeEach(() => resetDb(prisma));
afterAll(() => prisma.$disconnect());

describe("scan ingestion", () => {
  it("requests a rescan, creates the catalog from agent data, and records per-PC status", async () => {
    const ep = await prisma.endpoint.create({ data: { tenantId: TENANT_A, tacticalAgentId: "agentAAAA1111", hostname: "PC1" } });
    const t = tactical([upd(1, "g-1", false), upd(2, "g-2", true, "Low")]);

    const r = await ingestDueEndpoints(t);
    expect(r).toMatchObject({ rescanRequested: 1, ingested: 1, discovery: { products: 0, indexAvailable: expect.any(Boolean) } });
    expect(t.scanUpdates).toHaveBeenCalledWith("agentAAAA1111");

    const states = await prisma.endpointPatchState.findMany({ include: { patch: true }, orderBy: { tacticalUpdatePk: "asc" } });
    expect(states.map((s) => [s.patch.kb, s.patch.severity, s.status, s.tacticalUpdatePk])).toEqual([
      ["KB1", "CRITICAL", "NEEDED", 1],
      ["KB2", "LOW", "INSTALLED", 2],
    ]);
    expect((await prisma.endpoint.findUniqueOrThrow({ where: { id: ep.id } })).lastScanAt).not.toBeNull();
  });

  it("marks updates the agent stops reporting as NOT_APPLICABLE", async () => {
    const ep = await prisma.endpoint.create({ data: { tenantId: TENANT_A, tacticalAgentId: "agentBBBB2222", hostname: "PC2" } });
    await ingestDueEndpoints(tactical([upd(1, "g-1", false)]));
    await prisma.endpoint.update({ where: { id: ep.id }, data: { lastScanAt: null, ingestAttemptAt: null } });
    await ingestDueEndpoints(tactical([]));
    const s = await prisma.endpointPatchState.findFirstOrThrow({ where: { endpointId: ep.id } });
    expect(s.status).toBe("NOT_APPLICABLE");
  });

  it("tracks managed third-party apps only where installed", async () => {
    await prisma.endpoint.create({ data: { tenantId: TENANT_A, tacticalAgentId: "agentCCCC3333", hostname: "PC3" } });
    const app = await prisma.app.create({
      data: {
        wingetId: "Google.Chrome", displayName: "Chrome", inventoryMatch: "^Google Chrome$",
        expectedPublisher: "O=Google LLC", allowedDomains: ["dl.google.com"],
      },
    });
    const v = await prisma.appVersion.create({
      data: {
        appId: app.id, version: "130.0", installerUrl: "https://dl.google.com/x.msi", sha256: "a".repeat(64),
        silentArgs: "", verification: "VERIFIED", repoPath: "pkgs/x.msi", availableAt: new Date(Date.now() - 1000),
      },
    });
    await prisma.patch.create({ data: { kind: "THIRD_PARTY", externalId: "Google.Chrome@130.0", title: "Chrome 130", appVersionId: v.id } });

    // Not enabled for the bank yet: no compliance row.
    await ingestDueEndpoints(tactical([], [{ name: "Google Chrome", version: "128.0" }]));
    expect(await prisma.endpointPatchState.count({ where: { patch: { kind: "THIRD_PARTY" } } })).toBe(0);

    await prisma.tenantApp.create({ data: { tenantId: TENANT_A, appId: app.id, enabledBy: "admin@t" } });
    await prisma.endpoint.updateMany({ data: { lastScanAt: null, ingestAttemptAt: null } });
    await ingestDueEndpoints(tactical([], [{ name: "Google Chrome", version: "128.0" }]));
    const s = await prisma.endpointPatchState.findFirstOrThrow({ where: { patch: { kind: "THIRD_PARTY" } } });
    expect(s).toMatchObject({ status: "NEEDED", tenantId: TENANT_A });
  });
});

describe("starvation", () => {
  it("unreachable PCs do not block healthy ones", async () => {
    const { TacticalError } = await import("@/lib/tactical/client");
    // 25 offline PCs (more than one batch) created first, then one healthy PC
    for (let i = 0; i < 25; i++) {
      await prisma.endpoint.create({ data: { tenantId: TENANT_A, tacticalAgentId: `offline${String(i).padStart(6, "0")}`, hostname: `OFF${i}` } });
    }
    const healthy = await prisma.endpoint.create({ data: { tenantId: TENANT_A, tacticalAgentId: "healthyAgent01", hostname: "OK" } });
    const t = tactical([upd(1, "g-1", false)]);
    t.getUpdates = vi.fn(async (agentId: string) => {
      if (agentId.startsWith("offline")) throw new TacticalError("Tactical unreachable");
      return [upd(1, "g-1", false)];
    });
    t.scanUpdates = vi.fn(async (agentId: string) => {
      if (agentId.startsWith("offline")) throw new TacticalError("Tactical unreachable");
    });

    await ingestDueEndpoints(t); // first 20 offline fail
    await ingestDueEndpoints(t); // remaining 5 offline + healthy
    expect((await prisma.endpoint.findUniqueOrThrow({ where: { id: healthy.id } })).lastScanAt).not.toBeNull();
  });
});

describe("legacy Tactical link serves one bank only", () => {
  it("never scans or writes another bank's PCs", async () => {
    const other = await prisma.endpoint.create({ data: { tenantId: TENANT_B, tacticalAgentId: "bankBagent0001", hostname: "B-PC1" } });
    const mine = await prisma.endpoint.create({ data: { tenantId: TENANT_A, tacticalAgentId: "bankAagent0001", hostname: "A-PC1" } });
    const t = tactical([upd(1, "g-1", false)], [{ name: "7-Zip", version: "24.0" }]);

    const r = await ingestDueEndpoints(t);
    expect(r).toMatchObject({ rescanRequested: 1, ingested: 1 });
    expect(t.scanUpdates).toHaveBeenCalledWith("bankAagent0001");
    expect(t.scanUpdates).not.toHaveBeenCalledWith("bankBagent0001");

    const b = await prisma.endpoint.findUniqueOrThrow({ where: { id: other.id } });
    expect(b.lastScanAt).toBeNull();
    expect(b.lastScanRequestedAt).toBeNull();
    expect(await prisma.endpointPatchState.count({ where: { tenantId: TENANT_B } })).toBe(0);
    expect(await prisma.endpointPatchState.count({ where: { tenantId: TENANT_A, endpointId: mine.id } })).toBe(1);
    expect(await prisma.installedSoftware.count({ where: { tenantId: TENANT_A } })).toBe(1);
    expect(await prisma.discoveredApp.findMany({ select: { tenantId: true } })).toEqual([{ tenantId: TENANT_A }]);
  });
});
