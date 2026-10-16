import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { TacticalClient } from "@/lib/tactical/client";
import { TENANT_A, asSessionUser, configureTestEnv, resetDb } from "./helpers";

configureTestEnv({ TACTICAL_INSTALL_SCRIPT_ID: "77" });
const { prisma } = await import("@/lib/db");
const { ensureAgentUpgradePatch } = await import("@/lib/fetch/tactical");
const { createChangeRequest, applyAction } = await import("@/lib/approvals/service");
const { startDeployment } = await import("@/lib/deploy/start");
const { runWorkerTick } = await import("@/lib/deploy/worker");

function tactical(agentVersion: () => string) {
  const runScript = vi.fn(async () => "PATCHGATE_RESULT=OK");
  const client: TacticalClient = {
    listAgents: vi.fn(async () => []),
    getAgent: vi.fn(async () => ({ version: agentVersion(), goarch: "386" })),
    scanUpdates: vi.fn(async () => {}),
    getUpdates: vi.fn(async () => []),
    setUpdateAction: vi.fn(async () => {}),
    installApproved: vi.fn(async () => {}),
    getSoftware: vi.fn(async () => []),
    refreshSoftware: vi.fn(async () => {}),
    runScript,
  };
  return { client, runScript };
}

async function mirror(version: string, arch: "amd64" | "386", verification: "VERIFIED" | "PENDING" = "VERIFIED") {
  const asset = `tacticalagent-v${version}-windows-${arch}.exe`;
  return prisma.mirroredRelease.create({
    data: {
      component: "TACTICAL_AGENT",
      version,
      assetName: asset,
      sourceUrl: `https://github.com/amidaware/rmmagent/releases/download/v${version}/${asset}`,
      sha256: (arch === "386" ? "3" : "6").repeat(64),
      sizeBytes: BigInt(5_000_000),
      repoPath: `tactical/agent/${version}/${asset}`,
      verification,
    },
  });
}

beforeEach(() => resetDb(prisma));
afterAll(() => prisma.$disconnect());

describe("Tactical agent upgrade via change request", () => {
  it("approved build → patch → maker/checker → per-arch push → confirmed by reported agent version", async () => {
    await mirror("2.11.0", "amd64");
    await mirror("2.11.0", "386");
    await ensureAgentUpgradePatch("2.11.0");
    const patch = await prisma.patch.findUniqueOrThrow({ where: { externalId: "tactical-agent@2.11.0" } });
    expect(patch).toMatchObject({ kind: "AGENT_UPGRADE", agentVersion: "2.11.0" });

    const [maker, checker] = await Promise.all([
      prisma.user.create({ data: { upn: "m@t", name: "M", role: "OPERATOR" } }),
      prisma.user.create({ data: { upn: "c@t", name: "C", role: "APPROVER", tenantId: TENANT_A } }),
    ]);
    const ring = await prisma.ring.create({ data: { tenantId: TENANT_A, name: "R0", wsusGroup: "R0", order: 0 } });
    const ep = await prisma.endpoint.create({
      data: { tenantId: TENANT_A, tacticalAgentId: "agent32bit0001", hostname: "OLD-PC", ringId: ring.id, goarch: "386" },
    });
    const u = asSessionUser;

    const cr = await createChangeRequest(u(maker), TENANT_A, { title: "Agent 2.11.0", ringId: ring.id, patchIds: [patch.id] });
    await applyAction(u(maker), TENANT_A, cr.id, "submit");
    await applyAction(u(checker), TENANT_A, cr.id, "approve");
    await startDeployment(u(checker), TENANT_A, cr.id);

    let version = "2.10.0";
    const t = tactical(() => version);
    await runWorkerTick({ tactical: t.client, siem: null });

    const d = await prisma.deployment.findFirstOrThrow({ where: { endpointId: ep.id } });
    expect(d.status).toBe("SENT");
    expect(t.runScript).toHaveBeenCalledTimes(1);
    const env = (t.runScript.mock.calls[0] as unknown as [string, { envVars: Record<string, string> }])[1].envVars;
    expect(env).toMatchObject({ PG_KIND: "agent", PG_APP_ID: "Tactical.Agent", PG_SHA256: "3".repeat(64) });
    expect(env.PG_PATH).toMatch(/windows-386\.exe$/);

    // Not upgraded yet → stays SENT
    await runWorkerTick({ tactical: t.client, siem: null });
    expect((await prisma.deployment.findUniqueOrThrow({ where: { id: d.id } })).status).toBe("SENT");

    version = "2.11.0";
    await runWorkerTick({ tactical: t.client, siem: null });
    expect((await prisma.deployment.findUniqueOrThrow({ where: { id: d.id } })).status).toBe("SUCCEEDED");
    expect((await prisma.changeRequest.findUniqueOrThrow({ where: { id: cr.id } })).status).toBe("COMPLETED");
  });

  it("refuses a change request for an agent version with no approved build", async () => {
    await mirror("2.12.0", "amd64", "PENDING");
    await prisma.patch.create({ data: { kind: "AGENT_UPGRADE", externalId: "tactical-agent@2.12.0", title: "Agent 2.12.0", agentVersion: "2.12.0" } });
    const p = await prisma.patch.findUniqueOrThrow({ where: { externalId: "tactical-agent@2.12.0" } });
    const maker = await prisma.user.create({ data: { upn: "m@t", name: "M", role: "OPERATOR" } });
    const ring = await prisma.ring.create({ data: { tenantId: TENANT_A, name: "R0", wsusGroup: "R0", order: 0 } });
    await expect(
      createChangeRequest(asSessionUser(maker), TENANT_A, { title: "x", ringId: ring.id, patchIds: [p.id] }),
    ).rejects.toThrow(/no approved agent build/);
  });

  it("a newer approved build supersedes the older agent patch", async () => {
    for (const a of ["amd64", "386"] as const) await mirror("2.11.0", a);
    await ensureAgentUpgradePatch("2.11.0");
    for (const a of ["amd64", "386"] as const) await mirror("2.12.0", a);
    await ensureAgentUpgradePatch("2.12.0");
    const old = await prisma.patch.findUniqueOrThrow({ where: { externalId: "tactical-agent@2.11.0" } });
    const latest = await prisma.patch.findUniqueOrThrow({ where: { externalId: "tactical-agent@2.12.0" } });
    expect(old.supersededById).toBe(latest.id);
    expect(latest.supersededById).toBeNull();
  });

  it("approving an OLDER build after a newer one never creates a second live agent patch", async () => {
    for (const a of ["amd64", "386"] as const) await mirror("2.12.0", a);
    await ensureAgentUpgradePatch("2.12.0");
    for (const a of ["amd64", "386"] as const) await mirror("2.9.0", a);
    await ensureAgentUpgradePatch("2.9.0");
    const live = await prisma.patch.findMany({ where: { kind: "AGENT_UPGRADE", supersededById: null } });
    expect(live.map((p) => p.agentVersion)).toEqual(["2.12.0"]);
  });

  it("does not offer the upgrade until BOTH architectures are approved", async () => {
    await mirror("2.13.0", "amd64");
    await ensureAgentUpgradePatch("2.13.0");
    expect(await prisma.patch.count({ where: { externalId: "tactical-agent@2.13.0" } })).toBe(0);
    await mirror("2.13.0", "386");
    await ensureAgentUpgradePatch("2.13.0");
    expect(await prisma.patch.count({ where: { externalId: "tactical-agent@2.13.0" } })).toBe(1);
  });
});
