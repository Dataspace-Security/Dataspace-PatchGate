/**
 * Dev seed: two banks (tenants), our platform staff + bank users, per-bank rollout rings + window,
 * sample branch PCs with scan results, Windows patches and shared third-party apps (each bank opts in).
 * Refuses to run in production. Runs as the DB owner, so RLS does not apply here.
 *
 * Users (dev-login): admin@dev.local / operator@dev.local = PatchGate staff (all banks);
 * approver@dev.local / viewer@dev.local = Default bank; approver@bankb.local = Demo Bank B.
 */
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

const DEFAULT_BANK = { id: "tenant-default", slug: "default", name: "Default bank" };
const BANK_B = { id: "tenant-bank-b", slug: "bank-b", name: "Demo Bank B" };

type Role = "VIEWER" | "OPERATOR" | "APPROVER" | "ADMIN";

async function seedUsers(): Promise<void> {
  const users: { upn: string; name: string; role: Role; tenantId: string | null }[] = [
    { upn: "admin@dev.local", name: "Dev Admin", role: "ADMIN", tenantId: null },
    { upn: "operator@dev.local", name: "Dev Operator", role: "OPERATOR", tenantId: null },
    { upn: "approver@dev.local", name: "Dev Approver", role: "APPROVER", tenantId: DEFAULT_BANK.id },
    { upn: "viewer@dev.local", name: "Dev Viewer", role: "VIEWER", tenantId: DEFAULT_BANK.id },
    { upn: "approver@bankb.local", name: "Bank B Approver", role: "APPROVER", tenantId: BANK_B.id },
  ];
  for (const u of users) {
    await prisma.user.upsert({ where: { upn: u.upn }, create: u, update: { role: u.role, tenantId: u.tenantId } });
  }
}

/** Rings Test → Pilot → Prod + a Sunday window on Prod, for one bank. Returns ring ids by name. */
async function seedRings(tenantId: string): Promise<Map<string, string>> {
  const rings = [
    { name: "Ring0-Test", wsusGroup: "Ring0-Test", order: 0 },
    { name: "Ring1-Pilot", wsusGroup: "Ring1-Pilot", order: 1 },
    { name: "Ring2-Prod", wsusGroup: "Ring2-Prod", order: 2 },
  ];
  const ids = new Map<string, string>();
  for (const r of rings) {
    const row = await prisma.ring.upsert({
      where: { tenantId_name: { tenantId, name: r.name } },
      create: { tenantId, ...r },
      update: {},
    });
    ids.set(r.name, row.id);
  }
  const prod = ids.get("Ring2-Prod")!;
  if ((await prisma.maintenanceWindow.count({ where: { tenantId } })) === 0) {
    await prisma.maintenanceWindow.create({
      data: { tenantId, ringId: prod, name: "Sunday 02:00–04:00 IST", cron: "0 2 * * 0", durationMin: 120, timezone: "Asia/Kolkata" },
    });
  }
  return ids;
}

interface Pc {
  tacticalAgentId: string;
  hostname: string;
  site: string;
  ring: string | null;
}

async function seedEndpoints(tenantId: string, rings: Map<string, string>, pcs: Pc[], patchIds: string[]): Promise<void> {
  for (const [i, pc] of pcs.entries()) {
    const ep = await prisma.endpoint.upsert({
      where: { tacticalAgentId: pc.tacticalAgentId },
      create: {
        tenantId,
        tacticalAgentId: pc.tacticalAgentId,
        hostname: pc.hostname,
        site: pc.site,
        ringId: pc.ring ? rings.get(pc.ring)! : null,
        osName: "Windows 11 Enterprise 24H2",
        lastScanAt: new Date(),
        lastScanRequestedAt: new Date(),
      },
      update: {},
    });
    for (const [j, patchId] of patchIds.entries()) {
      const status = (i + j) % 3 === 0 ? "INSTALLED" : "NEEDED";
      await prisma.endpointPatchState.upsert({
        where: { endpointId_patchId: { endpointId: ep.id, patchId } },
        create: { tenantId, endpointId: ep.id, patchId, status, tacticalUpdatePk: 1000 + i * 10 + j },
        update: {},
      });
    }
  }
}

async function main(): Promise<void> {
  if (process.env.NODE_ENV === "production") throw new Error("Seed is dev-only");

  for (const t of [DEFAULT_BANK, BANK_B]) {
    await prisma.tenant.upsert({ where: { id: t.id }, create: t, update: { name: t.name } });
  }
  await seedUsers();

  // ---- Shared Windows catalog ----
  const patches = [
    { externalId: "3c1d2a10-0000-4000-8000-000000000001", kb: "KB5066001", title: "2026-10 Cumulative Update for Windows 11 24H2 (x64)", severity: "CRITICAL" as const, classification: "Security Updates" },
    { externalId: "3c1d2a10-0000-4000-8000-000000000002", kb: "KB5066002", title: "2026-10 .NET Framework 4.8.1 Security Update", severity: "IMPORTANT" as const, classification: "Security Updates" },
    { externalId: "3c1d2a10-0000-4000-8000-000000000003", kb: "KB2267602", title: "Microsoft Defender Antivirus definition update", severity: "UNSPECIFIED" as const, classification: "Definition Updates" },
  ];
  for (const p of patches) {
    await prisma.patch.upsert({ where: { externalId: p.externalId }, create: { kind: "WINDOWS", releasedAt: new Date(), ...p }, update: {} });
  }
  const patchIds = (await prisma.patch.findMany({ where: { externalId: { in: patches.map((p) => p.externalId) } } })).map((p) => p.id);

  // ---- Per bank: rings, window, PCs (agent ids are globally unique) ----
  const defaultRings = await seedRings(DEFAULT_BANK.id);
  await seedEndpoints(
    DEFAULT_BANK.id,
    defaultRings,
    [
      { tacticalAgentId: "devAgentBR001PC01", hostname: "BR001-PC01", site: "Pune Main", ring: "Ring0-Test" },
      { tacticalAgentId: "devAgentBR001PC02", hostname: "BR001-PC02", site: "Pune Main", ring: "Ring2-Prod" },
      { tacticalAgentId: "devAgentBR002PC01", hostname: "BR002-PC01", site: "Mumbai Fort", ring: "Ring2-Prod" },
      { tacticalAgentId: "devAgentBR002PC02", hostname: "BR002-PC02", site: "Mumbai Fort", ring: null },
    ],
    patchIds,
  );
  const bankBRings = await seedRings(BANK_B.id);
  await seedEndpoints(
    BANK_B.id,
    bankBRings,
    [
      { tacticalAgentId: "devAgentBNKB-HQ-PC01", hostname: "BNKB-HQ-PC01", site: "Bengaluru HQ", ring: "Ring0-Test" },
      { tacticalAgentId: "devAgentBNKB-HQ-PC02", hostname: "BNKB-HQ-PC02", site: "Bengaluru HQ", ring: "Ring2-Prod" },
      { tacticalAgentId: "devAgentBNKB-CH-PC01", hostname: "BNKB-CH-PC01", site: "Chennai Branch", ring: "Ring2-Prod" },
    ],
    patchIds,
  );

  // ---- Shared third-party allow-list ----
  const ps = await prisma.app.upsert({
    where: { wingetId: "Microsoft.PowerShell" },
    create: {
      wingetId: "Microsoft.PowerShell",
      displayName: "PowerShell 7",
      inventoryMatch: "^PowerShell 7",
      expectedPublisher: "O=Microsoft Corporation",
      allowedDomains: ["github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"],
    },
    update: {},
  });

  // ---- Dynamic third-party (dev only): a managed app whose first download awaits a signer decision ----
  const npp = await prisma.app.upsert({
    where: { wingetId: "Notepad++.Notepad++" },
    create: { wingetId: "Notepad++.Notepad++", displayName: "Notepad++", inventoryMatch: "^Notepad\\+\\+(?![\\w+])", expectedPublisher: null, allowedDomains: [] },
    update: {},
  });
  await prisma.appVersion.upsert({
    where: { appId_version: { appId: npp.id, version: "8.9.8.1" } },
    create: {
      appId: npp.id, version: "8.9.8.1", installerUrl: "https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.9.8.1/npp.8.9.8.1.Installer.x64.msi",
      sha256: "3f1c2a9e8b7d6c5f4e3d2c1b0a99887766554433221100ffeeddccbbaa998877", catalogSha256: "3f1c2a9e8b7d6c5f4e3d2c1b0a99887766554433221100ffeeddccbbaa998877",
      silentArgs: "", installerKind: "MSI", installerType: "wix", verification: "HELD", holdReason: "FIRST_SIGNER",
      signerOrg: "NOTEPAD++", signerSubject: "CN=NOTEPAD++, O=NOTEPAD++, C=FR", fileVersion: "8.9.8.1",
      repoPath: "pkgs/Notepad-Notepad/8.9.8.1/Notepad-Notepad-8.9.8.1.msi",
    },
    update: {},
  });

  // ---- Bank opt-ins: Default bank uses both apps, Bank B only PowerShell ----
  const optIns = [
    { tenantId: DEFAULT_BANK.id, appId: ps.id },
    { tenantId: DEFAULT_BANK.id, appId: npp.id },
    { tenantId: BANK_B.id, appId: ps.id },
  ];
  for (const o of optIns) {
    await prisma.tenantApp.upsert({
      where: { tenantId_appId: o },
      create: { ...o, enabledBy: "admin@dev.local" },
      update: {},
    });
  }

  // ---- Discovery (per bank) ----
  const discovered = [
    { tenantId: DEFAULT_BANK.id, key: "7zipedition|igorpavlov", displayName: "7-Zip 26.01 (x64 edition)", publisher: "Igor Pavlov", wingetId: "7zip.7zip", match: "PRODUCT_CODE" as const, endpointCount: 4, versions: ["25.00.00.0", "26.01.00.0"], appId: null },
    { tenantId: DEFAULT_BANK.id, key: "mozillafirefox|mozilla", displayName: "Mozilla Firefox (x64 en-US)", publisher: "Mozilla", wingetId: "Mozilla.Firefox", match: "NAME_PUBLISHER" as const, endpointCount: 3, versions: ["156.0", "157.0.1"], appId: null },
    { tenantId: DEFAULT_BANK.id, key: "notepad|notepadteam", displayName: "Notepad++ (64-bit x64)", publisher: "Notepad++ Team", wingetId: "Notepad++.Notepad++", match: "NAME_PUBLISHER" as const, endpointCount: 2, versions: ["8.9.6.4"], appId: npp.id },
    { tenantId: DEFAULT_BANK.id, key: "powershell7|microsoft", displayName: "PowerShell 7-x64", publisher: "Microsoft Corporation", wingetId: "Microsoft.PowerShell", match: "PRODUCT_CODE" as const, endpointCount: 4, versions: ["7.6.4.0"], appId: ps.id },
    { tenantId: DEFAULT_BANK.id, key: "adobeacrobat|adobe", displayName: "Adobe Acrobat (64-bit)", publisher: "Adobe", wingetId: null, match: "NONE" as const, endpointCount: 2, versions: ["25.001.20432"], appId: null },
    { tenantId: DEFAULT_BANK.id, key: "bankteller|examplebankit", displayName: "Bank Teller Client 4.2", publisher: "Example Bank IT", wingetId: null, match: "NONE" as const, endpointCount: 4, versions: ["4.2"], appId: null },
    { tenantId: BANK_B.id, key: "powershell7|microsoft", displayName: "PowerShell 7-x64", publisher: "Microsoft Corporation", wingetId: "Microsoft.PowerShell", match: "PRODUCT_CODE" as const, endpointCount: 3, versions: ["7.5.2.0"], appId: ps.id },
    { tenantId: BANK_B.id, key: "googlechrome|google", displayName: "Google Chrome", publisher: "Google LLC", wingetId: "Google.Chrome", match: "NAME_PUBLISHER" as const, endpointCount: 3, versions: ["141.0.7390.55"], appId: null },
    { tenantId: BANK_B.id, key: "corebankingterminal|bankbit", displayName: "Core Banking Terminal 9", publisher: "Bank B IT", wingetId: null, match: "NONE" as const, endpointCount: 3, versions: ["9.1"], appId: null },
  ];
  for (const d of discovered) {
    await prisma.discoveredApp.upsert({ where: { tenantId_key: { tenantId: d.tenantId, key: d.key } }, create: d, update: {} });
  }
}

main()
  .catch((err: unknown) => {
    console.error(err);
    process.exitCode = 1;
  })
  .finally(() => prisma.$disconnect());
