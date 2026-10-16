/**
 * Windows patches a PatchGate-sourced bank cannot get delivered (DB integration): a patch that only Tactical's
 * own online scan listed (no WinUpdate row = no PatchGate offline-scan evidence) is refused at create / submit
 * with "Needs PatchGate scan", before maker + checker spend time on it. TENANT_B = connector bank (PATCHGATE).
 */
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { TENANT_A, TENANT_B, asSessionUser, configureTestEnv, resetDb } from "./helpers";

configureTestEnv();

const { prisma } = await import("@/lib/db");
const { withTenant } = await import("@/lib/tenancy");
const { createChangeRequest, applyAction } = await import("@/lib/approvals/service");
const { requiresOfflineWindowsScan } = await import("@/lib/approvals/load-eligible");

const TACTICAL_ONLY = "22222222-3333-4444-5555-666666666666";
const SCANNED = "33333333-4444-5555-6666-777777777777";

let maker: ReturnType<typeof asSessionUser>;
let ringId = "";

beforeEach(async () => {
  await prisma.$executeRawUnsafe(`DELETE FROM "WinUpdateFile"`);
  await prisma.$executeRawUnsafe(`DELETE FROM "WinUpdate"`);
  await resetDb(prisma);
  maker = asSessionUser(await prisma.user.create({ data: { upn: "maker@pg.example", name: "Maker", role: "ADMIN" } }));
  ringId = (await prisma.ring.create({ data: { tenantId: TENANT_B, name: "Ring0", wsusGroup: "Ring0", order: 0 } })).id;
  await prisma.winUpdate.create({ data: { id: SCANNED, revision: 0, title: "pending", firstTenantId: TENANT_B } });
});

afterAll(() => prisma.$disconnect());

const patch = (externalId: string, title: string) => prisma.patch.create({ data: { kind: "WINDOWS", externalId, title, severity: "IMPORTANT" } });

describe("Windows patches without PatchGate offline-scan evidence", () => {
  it("refuses create; accepts a patch the offline scan reported; refuses submit if one slipped in", async () => {
    const tacticalOnly = await patch(TACTICAL_ONLY, "2026-10 .NET Framework Security Update (KB5127690)");
    const scanned = await patch(SCANNED, "2026-10 Cumulative Update");

    await expect(createChangeRequest(maker, TENANT_B, { title: "x", ringId, patchIds: [tacticalOnly.id] })).rejects.toMatchObject({
      status: 422,
      message: expect.stringContaining("Needs PatchGate scan"),
    });
    const cr = await createChangeRequest(maker, TENANT_B, { title: "ok", ringId, patchIds: [scanned.id] });

    // A request drafted before the rule (or a patch whose catalog entry went away): submit refuses it too.
    await prisma.changeRequestPatch.create({ data: { changeRequestId: cr.id, patchId: tacticalOnly.id } });
    await expect(applyAction(maker, TENANT_B, cr.id, "submit")).rejects.toMatchObject({ status: 422, message: expect.stringContaining("Needs PatchGate scan") });
    expect((await prisma.changeRequest.findUniqueOrThrow({ where: { id: cr.id } })).status).toBe("DRAFT");

    await prisma.changeRequestPatch.delete({ where: { changeRequestId_patchId: { changeRequestId: cr.id, patchId: tacticalOnly.id } } });
    await applyAction(maker, TENANT_B, cr.id, "submit");
  });

  it("UNRESOLVABLE updates are refused as well; WSUS banks and the legacy direct-Tactical bank are not checked", async () => {
    await prisma.winUpdate.update({ where: { id: SCANNED }, data: { catalogState: "UNRESOLVABLE" } });
    const scanned = await patch(SCANNED, "CU");
    await expect(createChangeRequest(maker, TENANT_B, { title: "x", ringId, patchIds: [scanned.id] })).rejects.toThrow(/no Microsoft download/);

    expect(await withTenant(TENANT_A, (tx) => requiresOfflineWindowsScan(tx, TENANT_A))).toBe(false); // legacy direct link (test env)
    expect(await withTenant(TENANT_B, (tx) => requiresOfflineWindowsScan(tx, TENANT_B))).toBe(true);
    await prisma.tenant.update({ where: { id: TENANT_B }, data: { windowsUpdateSource: "WSUS" } });
    expect(await withTenant(TENANT_B, (tx) => requiresOfflineWindowsScan(tx, TENANT_B))).toBe(false);
    await createChangeRequest(maker, TENANT_B, { title: "wsus", ringId, patchIds: [scanned.id] });
  });
});
