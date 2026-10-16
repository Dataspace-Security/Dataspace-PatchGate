/**
 * Integration tests against a real PostgreSQL (TEST database only).
 * Run: npm run test:int   (requires TEST_DATABASE_URL, see package.json)
 */
import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";
import { TENANT_A, asSessionUser, configureTestEnv, resetDb } from "./helpers";
import type { TacticalClient } from "@/lib/tactical/client";
import type { TacticalWinUpdate } from "@/lib/tactical/types";

configureTestEnv();

const { prisma } = await import("@/lib/db");
const { createChangeRequest, applyAction } = await import("@/lib/approvals/service");
const { startDeployment } = await import("@/lib/deploy/start");
const { runWorkerTick } = await import("@/lib/deploy/worker");
const { verifyAuditLog } = await import("@/lib/audit/service");

const GUID = "11111111-1111-1111-1111-111111111111";

function fakeTactical(installed: () => boolean): TacticalClient {
  const state: TacticalWinUpdate[] = [
    { id: 1, guid: GUID, kb: "KB1", title: "t", installed: false, action: "nothing", severity: "Critical" },
  ];
  return {
    listAgents: vi.fn(async () => []),
    getAgent: vi.fn(async () => ({ version: "2.11.0", goarch: "amd64" })),
    scanUpdates: vi.fn(async () => {}),
    getUpdates: vi.fn(async () => state.map((u) => ({ ...u, installed: installed() }))),
    setUpdateAction: vi.fn(async (pk, action) => {
      const u = state.find((x) => x.id === pk);
      if (u) u.action = action;
    }),
    installApproved: vi.fn(async () => {}),
    getSoftware: vi.fn(async () => []),
    refreshSoftware: vi.fn(async () => {}),
    runScript: vi.fn(async () => "PATCHGATE_RESULT=OK"),
  };
}

async function seed() {
  // Platform operator prepares (maker); the bank's own approver decides (checker).
  const [maker, checker] = await Promise.all([
    prisma.user.create({ data: { upn: "maker@t", name: "Maker", role: "ADMIN" } }),
    prisma.user.create({ data: { upn: "checker@t", name: "Checker", role: "ADMIN", tenantId: TENANT_A } }),
  ]);
  const ring = await prisma.ring.create({ data: { tenantId: TENANT_A, name: "Ring0", wsusGroup: "Ring0", order: 0 } });
  const endpoint = await prisma.endpoint.create({
    data: { tenantId: TENANT_A, tacticalAgentId: "agentABCDEFGH", hostname: "BR001-PC01", ringId: ring.id },
  });
  const patch = await prisma.patch.create({
    data: { kind: "WINDOWS", externalId: GUID, kb: "KB1", title: "KB1", severity: "CRITICAL" },
  });
  return { maker: asSessionUser(maker), checker: asSessionUser(checker), ring, endpoint, patch };
}

beforeEach(() => resetDb(prisma));
afterAll(() => prisma.$disconnect());

describe("database guarantees", () => {
  it("audit log rejects UPDATE and DELETE", async () => {
    const { maker, ring, patch } = await seed();
    await createChangeRequest(maker, TENANT_A, { title: "x", ringId: ring.id, patchIds: [patch.id] });
    await expect(prisma.$executeRawUnsafe(`UPDATE "AuditEvent" SET actor='evil'`)).rejects.toThrow(/append-only/);
    await expect(prisma.$executeRawUnsafe(`DELETE FROM "AuditEvent"`)).rejects.toThrow(/append-only/);
  });

  it("allows only one in-flight deployment per endpoint", async () => {
    const { maker, ring, patch, endpoint } = await seed();
    const a = await createChangeRequest(maker, TENANT_A, { title: "a", ringId: ring.id, patchIds: [patch.id] });
    const b = await createChangeRequest(maker, TENANT_A, { title: "b", ringId: ring.id, patchIds: [patch.id] });
    await prisma.deployment.create({ data: { tenantId: TENANT_A, changeRequestId: a.id, endpointId: endpoint.id, status: "SENT" } });
    await expect(
      prisma.deployment.create({ data: { tenantId: TENANT_A, changeRequestId: b.id, endpointId: endpoint.id, status: "SENDING" } }),
    ).rejects.toMatchObject({ code: "P2002" });
  });
});

describe("end-to-end change request", () => {
  it("enforces maker-checker, deploys via worker, confirms, and keeps a valid audit chain", async () => {
    const { maker, checker, ring, patch, endpoint } = await seed();
    const cr = await createChangeRequest(maker, TENANT_A, { title: "Oct PT", ringId: ring.id, patchIds: [patch.id] });

    await applyAction(maker, TENANT_A, cr.id, "submit");
    await expect(applyAction({ ...maker, role: "ADMIN", tenantId: TENANT_A }, TENANT_A, cr.id, "approve")).rejects.toThrow(/Maker-checker/);
    await applyAction(checker, TENANT_A, cr.id, "approve");

    await expect(startDeployment({ ...maker, role: "AUDITOR" }, TENANT_A, cr.id)).rejects.toThrow();
    await startDeployment(checker, TENANT_A, cr.id);
    expect(await prisma.deployment.count({ where: { changeRequestId: cr.id, status: "QUEUED" } })).toBe(1);

    let installed = false;
    const tactical = fakeTactical(() => installed);

    await runWorkerTick({ tactical, siem: null });
    const sent = await prisma.deployment.findFirstOrThrow({ where: { endpointId: endpoint.id } });
    expect(sent.status).toBe("SENT");
    expect(sent.targetGuids).toEqual([GUID]);
    expect(tactical.installApproved).toHaveBeenCalledTimes(1);

    // Not yet installed on the agent → stays SENT, CR stays DEPLOYING
    await runWorkerTick({ tactical, siem: null });
    expect((await prisma.changeRequest.findUniqueOrThrow({ where: { id: cr.id } })).status).toBe("DEPLOYING");

    installed = true;
    await runWorkerTick({ tactical, siem: null });
    expect((await prisma.deployment.findFirstOrThrow({ where: { id: sent.id } })).status).toBe("SUCCEEDED");
    expect((await prisma.changeRequest.findUniqueOrThrow({ where: { id: cr.id } })).status).toBe("COMPLETED");

    const audit = await verifyAuditLog(TENANT_A);
    expect(audit.valid).toBe(true);
    // The whole lifecycle lives in the bank's own chain; nothing leaked into the platform chain.
    expect(await prisma.auditEvent.count({ where: { tenantId: null } })).toBe(0);
    const actions = (await prisma.auditEvent.findMany({ where: { tenantId: TENANT_A }, orderBy: { seq: "asc" } })).map((a) => a.action);
    expect(actions).toEqual([
      "change_request.create",
      "change_request.submit",
      "change_request.approve",
      "change_request.deploy",
      "deployment.succeeded",
      "change_request.finalise",
    ]);
  });

  it("refuses to queue a deployment for a ring with no endpoints (no stuck DEPLOYING)", async () => {
    const { maker, checker, patch } = await seed();
    const empty = await prisma.ring.create({ data: { tenantId: TENANT_A, name: "Empty", wsusGroup: "Empty", order: 9 } });
    const cr = await createChangeRequest(maker, TENANT_A, { title: "x", ringId: empty.id, patchIds: [patch.id] });
    await applyAction(maker, TENANT_A, cr.id, "submit");
    await applyAction(checker, TENANT_A, cr.id, "approve");
    await expect(startDeployment(checker, TENANT_A, cr.id)).rejects.toThrow(/no endpoints/);
    expect((await prisma.changeRequest.findUniqueOrThrow({ where: { id: cr.id } })).status).toBe("APPROVED");
  });
});

describe("transient Tactical outages", () => {
  it("requeues on 'Tactical unreachable' instead of failing, then succeeds when it is back", async () => {
    const { TacticalError } = await import("@/lib/tactical/client");
    const { maker, checker, ring, patch, endpoint } = await seed();
    const cr = await createChangeRequest(maker, TENANT_A, { title: "x", ringId: ring.id, patchIds: [patch.id] });
    await applyAction(maker, TENANT_A, cr.id, "submit");
    await applyAction(checker, TENANT_A, cr.id, "approve");
    await startDeployment(checker, TENANT_A, cr.id);

    const down = fakeTactical(() => false);
    down.getUpdates = vi.fn(async () => {
      throw new TacticalError("Tactical unreachable (GET /winupdate/x/): fetch failed");
    });
    await runWorkerTick({ tactical: down, siem: null });
    const d1 = await prisma.deployment.findFirstOrThrow({ where: { endpointId: endpoint.id } });
    expect(d1.status).toBe("QUEUED");
    expect(d1.note).toMatch(/unreachable/);

    // make it due again and bring Tactical back
    await prisma.deployment.update({ where: { id: d1.id }, data: { nextAttemptAt: new Date(0) } });
    await runWorkerTick({ tactical: fakeTactical(() => false), siem: null });
    expect((await prisma.deployment.findUniqueOrThrow({ where: { id: d1.id } })).status).toBe("SENT");
  });

  it("still fails immediately on a 4xx from Tactical (e.g. bad API key)", async () => {
    const { TacticalError } = await import("@/lib/tactical/client");
    const { maker, checker, ring, patch, endpoint } = await seed();
    const cr = await createChangeRequest(maker, TENANT_A, { title: "x", ringId: ring.id, patchIds: [patch.id] });
    await applyAction(maker, TENANT_A, cr.id, "submit");
    await applyAction(checker, TENANT_A, cr.id, "approve");
    await startDeployment(checker, TENANT_A, cr.id);

    const denied = fakeTactical(() => false);
    denied.getUpdates = vi.fn(async () => {
      throw new TacticalError("Tactical GET /winupdate/x/ -> 403", 403);
    });
    await runWorkerTick({ tactical: denied, siem: null });
    expect((await prisma.deployment.findFirstOrThrow({ where: { endpointId: endpoint.id } })).status).toBe("FAILED");
  });
});
