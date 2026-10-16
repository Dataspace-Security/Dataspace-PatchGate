import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { TENANT_A, TENANT_B, configureTestEnv, resetDb } from "./helpers";

configureTestEnv();
const { prisma } = await import("@/lib/db");
const { ingestWsusCatalog, wsusDesiredState, wsusBatchSchema } = await import("@/lib/wsus/catalog");

const OLD = "AAAAAAAA-0000-0000-0000-000000000001";
const NEW = "aaaaaaaa-0000-0000-0000-000000000002";

beforeEach(() => resetDb(prisma));
afterAll(() => prisma.$disconnect());

describe("WSUS catalog ingestion", () => {
  it("upserts metadata, normalises GUID case, and links supersedence in any order", async () => {
    const batch = wsusBatchSchema.parse({
      updates: [
        { updateId: OLD, title: "2026-09 CU", kb: "5050001", classification: "Security Updates", msrcSeverity: "Critical", released: "2026-09-09T00:00:00Z", supersededBy: NEW },
        { updateId: NEW, title: "2026-10 CU", kb: "5060002", classification: "Security Updates", msrcSeverity: "Important", released: "2026-10-14T00:00:00Z" },
      ],
    });
    expect(await ingestWsusCatalog(batch.updates)).toEqual({ upserted: 2, superseded: 1 });

    const oldP = await prisma.patch.findUniqueOrThrow({ where: { externalId: OLD.toLowerCase() } });
    const newP = await prisma.patch.findUniqueOrThrow({ where: { externalId: NEW } });
    expect(oldP).toMatchObject({ kb: "KB5050001", severity: "CRITICAL", supersededById: newP.id });
    expect(newP.severity).toBe("IMPORTANT");
  });

  it("rejects malformed payloads (schema)", () => {
    expect(wsusBatchSchema.safeParse({ updates: [{ updateId: "not-a-guid", title: "x" }] }).success).toBe(false);
    expect(wsusBatchSchema.safeParse({ updates: [] }).success).toBe(false);
  });

  it("approves only while DEPLOYING (not at APPROVED), and lists every managed group for revocation", async () => {
    const u = await prisma.user.create({ data: { upn: "m@t", name: "M", role: "OPERATOR" } });
    const ring = await prisma.ring.create({ data: { tenantId: TENANT_A, name: "Pilot", wsusGroup: "Ring1-Pilot", order: 1 } });
    // Another bank on the same platform: its rings / deployments never reach the legacy WSUS server.
    const ringB = await prisma.ring.create({ data: { tenantId: TENANT_B, name: "B-Prod", wsusGroup: "BankB-Prod", order: 2 } });
    await ingestWsusCatalog(wsusBatchSchema.parse({ updates: [{ updateId: NEW, title: "CU" }] }).updates);
    const p = await prisma.patch.findUniqueOrThrow({ where: { externalId: NEW } });

    for (const status of ["DRAFT", "APPROVED", "DEPLOYING", "REJECTED"] as const) {
      await prisma.changeRequest.create({
        data: { tenantId: TENANT_A, title: status, ringId: ring.id, createdById: u.id, status, patches: { create: [{ patchId: p.id }] } },
      });
    }
    await prisma.changeRequest.create({
      data: { tenantId: TENANT_B, title: "B", ringId: ringB.id, createdById: u.id, status: "DEPLOYING", patches: { create: [{ patchId: p.id }] } },
    });
    expect(await wsusDesiredState()).toEqual({ groups: ["Ring1-Pilot"], approvals: [{ updateId: NEW, wsusGroup: "Ring1-Pilot" }] });
    await prisma.changeRequest.updateMany({ where: { tenantId: TENANT_A, status: "DEPLOYING" }, data: { status: "CANCELLED" } });
    expect((await wsusDesiredState()).approvals).toEqual([]);
  });
});
