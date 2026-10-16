import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { TacticalClient } from "@/lib/tactical/client";
import type { SoftwareItem } from "@/lib/tactical/types";
import { TENANT_A, TENANT_B, configureTestEnv, resetDb } from "./helpers";

const repoDir = mkdtempSync(join(tmpdir(), "pg-trust-"));
configureTestEnv({ REPO_DIR: repoDir, QUARANTINE_HOURS: "48" });
const { prisma } = await import("@/lib/db");
const { ingestDueEndpoints } = await import("@/lib/scan/ingest");
const { manageDiscovered, setDiscoveredIgnored } = await import("@/lib/discovery/service");
const { indexPath } = await import("@/lib/discovery/winget-index");
const { decidePackage } = await import("@/lib/fetch/thirdparty");
const { pendingAbs, repoAbsPath } = await import("@/lib/fetch/repo");

/** Minimal winget index with the real table layout. */
function buildIndex(entries: { id: string; names: string[]; publisher: string; codes?: string[] }[]): void {
  const path = indexPath(repoDir);
  mkdirSync(dirname(path), { recursive: true });
  rmSync(path, { force: true });
  const db = new DatabaseSync(path);
  db.exec(`
    CREATE TABLE ids(id TEXT); CREATE TABLE manifest(id INT, name INT, version TEXT);
    CREATE TABLE productcodes(productcode TEXT); CREATE TABLE productcodes_map(manifest INT, productcode INT);
    CREATE TABLE norm_names(norm_name TEXT); CREATE TABLE norm_names_map(manifest INT, norm_name INT);
    CREATE TABLE norm_publishers(norm_publisher TEXT); CREATE TABLE norm_publishers_map(manifest INT, norm_publisher INT);`);
  const ins = (sql: string, ...v: (string | number | bigint)[]) => Number(db.prepare(sql).run(...v).lastInsertRowid);
  for (const e of entries) {
    const idRow = ins("INSERT INTO ids(id) VALUES (?)", e.id);
    const m = ins("INSERT INTO manifest(id, name, version) VALUES (?, 0, '1')", idRow);
    const pub = ins("INSERT INTO norm_publishers(norm_publisher) VALUES (?)", e.publisher);
    ins("INSERT INTO norm_publishers_map VALUES (?, ?)", m, pub);
    for (const n of e.names) ins("INSERT INTO norm_names_map VALUES (?, ?)", m, ins("INSERT INTO norm_names(norm_name) VALUES (?)", n));
    for (const c of e.codes ?? []) ins("INSERT INTO productcodes_map VALUES (?, ?)", m, ins("INSERT INTO productcodes(productcode) VALUES (?)", c));
  }
  db.close();
}

function tactical(softwareByAgent: Record<string, SoftwareItem[]>): TacticalClient {
  return {
    listAgents: vi.fn(async () => []),
    getAgent: vi.fn(async () => ({ version: "2.11.0", goarch: "amd64" })),
    scanUpdates: vi.fn(async () => {}),
    getUpdates: vi.fn(async () => []),
    setUpdateAction: vi.fn(async () => {}),
    installApproved: vi.fn(async () => {}),
    getSoftware: vi.fn(async (agentId: string) => softwareByAgent[agentId] ?? []),
    refreshSoftware: vi.fn(async () => {}),
    runScript: vi.fn(async () => ""),
  };
}

const SEVEN_ZIP_CODE = "{23170f69-40c1-2702-2601-000001000000}";
const sevenZip = (v: string): SoftwareItem => ({
  name: `7-Zip ${v} (x64 edition)`, version: `${v}.00.0`, publisher: "Igor Pavlov",
  uninstall: `MsiExec.exe /I${SEVEN_ZIP_CODE.toUpperCase()}`,
});
const git: SoftwareItem = { name: "Git", version: "2.55.0", publisher: "The Git Development Community", uninstall: '"C:\\Program Files\\Git\\unins000.exe"' };
const internal: SoftwareItem = { name: "Bank Teller Client 4.2", version: "4.2", publisher: "Example Bank IT" };

beforeEach(async () => {
  await resetDb(prisma);
  rmSync(join(repoDir, "pkgs"), { recursive: true, force: true });
  rmSync(join(repoDir, ".pending"), { recursive: true, force: true });
});
afterAll(async () => {
  await prisma.$disconnect();
  rmSync(repoDir, { recursive: true, force: true });
});

describe("fleet discovery", () => {
  it("records inventory, matches products to winget, and turns a match into a managed app", async () => {
    buildIndex([
      { id: "7zip.7zip", names: ["7zip(X64)"], publisher: "igorpavlov", codes: [SEVEN_ZIP_CODE] },
      { id: "Git.Git", names: ["git"], publisher: "thegitdevelopmentcommunity" },
      { id: "Microsoft.Git", names: ["git"], publisher: "thegitclientteamatmicrosoft" },
    ]);
    await prisma.endpoint.create({ data: { tenantId: TENANT_A, tacticalAgentId: "agentPC000001", hostname: "PC1" } });
    await prisma.endpoint.create({ data: { tenantId: TENANT_A, tacticalAgentId: "agentPC000002", hostname: "PC2" } });

    const r = await ingestDueEndpoints(tactical({ agentPC000001: [sevenZip("26.01"), git, internal], agentPC000002: [sevenZip("25.00")] }));
    expect(r.discovery).toEqual({ products: 3, matched: 2, indexAvailable: true });
    expect(await prisma.installedSoftware.count()).toBe(4);

    const found = await prisma.discoveredApp.findMany({ orderBy: { displayName: "asc" } });
    expect(found.map((d) => [d.displayName, d.wingetId, d.match, d.endpointCount, d.versions.sort()])).toEqual([
      ["7-Zip 25.00 (x64 edition)", "7zip.7zip", "PRODUCT_CODE", 2, ["25.00.00.0", "26.01.00.0"]],
      ["Bank Teller Client 4.2", null, "NONE", 1, ["4.2"]],
      ["Git", "Git.Git", "NAME_PUBLISHER", 1, ["2.55.0"]],
    ]);

    const seven = found[0];
    // Another bank can neither see nor manage this bank's discovered products.
    await expect(manageDiscovered(TENANT_B, seven.id, "admin@bankb")).rejects.toThrow(/not found/);
    await expect(setDiscoveredIgnored(TENANT_B, found[1].id, true, "admin@bankb")).rejects.toThrow(/not found/);

    // A PLATFORM admin may add a discovered product to the shared allow-list (bank admins only request it).
    const { appId } = await manageDiscovered(TENANT_A, seven.id, { upn: "admin@bank", platformAdmin: true });
    const app = await prisma.app.findUniqueOrThrow({ where: { id: appId! } });
    expect(app).toMatchObject({ wingetId: "7zip.7zip", expectedPublisher: null, allowedDomains: [], strictHosts: false });
    expect(new RegExp(app.inventoryMatch).test("7-Zip 26.04 (x64 edition)")).toBe(true);
    // "Manage" also opts the bank in to the shared app.
    expect(await prisma.tenantApp.findMany({ select: { tenantId: true, appId: true } })).toEqual([{ tenantId: TENANT_A, appId }]);
    await expect(manageDiscovered(TENANT_A, seven.id, "admin@bank")).rejects.toThrow(/Already managed/);
    await expect(manageDiscovered(TENANT_A, found[1].id, "admin@bank")).rejects.toThrow(/No winget package/);

    await setDiscoveredIgnored(TENANT_A, found[1].id, true, "admin@bank");
    expect((await prisma.discoveredApp.findUniqueOrThrow({ where: { id: found[1].id } })).ignored).toBe(true);
    // Bank actions are recorded in the bank's own chain.
    const actions = (await prisma.auditEvent.findMany({ where: { tenantId: TENANT_A }, orderBy: { seq: "asc" } })).map((a) => a.action);
    expect(actions).toEqual(expect.arrayContaining(["app.allowlist_add", "discovery.ignore"]));
    expect(await prisma.auditEvent.count({ where: { tenantId: { not: TENANT_A } } })).toBe(0);
  });

  it("keeps managed products and drops unmanaged ones that are no longer installed anywhere", async () => {
    buildIndex([{ id: "7zip.7zip", names: ["7zip(X64)"], publisher: "igorpavlov", codes: [SEVEN_ZIP_CODE] }]);
    const ep = await prisma.endpoint.create({ data: { tenantId: TENANT_A, tacticalAgentId: "agentPC000003", hostname: "PC3" } });
    await ingestDueEndpoints(tactical({ agentPC000003: [sevenZip("26.01"), internal] }));
    const seven = await prisma.discoveredApp.findFirstOrThrow({ where: { wingetId: "7zip.7zip" } });
    await manageDiscovered(TENANT_A, seven.id, { upn: "admin@bank", platformAdmin: true });

    await prisma.endpoint.update({ where: { id: ep.id }, data: { lastScanAt: null, ingestAttemptAt: null } });
    await ingestDueEndpoints(tactical({ agentPC000003: [] }));
    const left = await prisma.discoveredApp.findMany();
    expect(left.map((d) => [d.wingetId, d.endpointCount])).toEqual([["7zip.7zip", 0]]);
  });

  it("lists products without matching when the index has not been downloaded", async () => {
    rmSync(indexPath(repoDir), { force: true });
    await prisma.endpoint.create({ data: { tenantId: TENANT_A, tacticalAgentId: "agentPC000004", hostname: "PC4" } });
    const r = await ingestDueEndpoints(tactical({ agentPC000004: [git] }));
    expect(r.discovery).toEqual({ products: 1, matched: 0, indexAvailable: false });
  });
});

describe("held package trust decisions", () => {
  async function held(opts: { version: string; holdReason: "FIRST_SIGNER" | "SIGNER_CHANGED" | "HASH_DRIFT"; signerOrg: string; pins: string | null; appId?: string }) {
    const app =
      opts.appId
        ? await prisma.app.findUniqueOrThrow({ where: { id: opts.appId } })
        : await prisma.app.create({ data: { wingetId: "7zip.7zip", displayName: "7-Zip", inventoryMatch: "^7-Zip", expectedPublisher: opts.pins, allowedDomains: [] } });
    const repoPath = `pkgs/7zip.7zip/${opts.version}/7zip.7zip-${opts.version}.msi`;
    const bytes = Buffer.from(`installer ${opts.version}`);
    const file = pendingAbs(repoDir, repoPath);
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(file, bytes);
    const sha256 = createHash("sha256").update(bytes).digest("hex");
    const v = await prisma.appVersion.create({
      data: {
        appId: app.id, version: opts.version, installerUrl: "https://github.com/x.msi", sha256, catalogSha256: opts.holdReason === "HASH_DRIFT" ? "f".repeat(64) : sha256,
        silentArgs: "", verification: "HELD", holdReason: opts.holdReason, signerOrg: opts.signerOrg, signerSubject: `CN=${opts.signerOrg}, O=${opts.signerOrg}`, repoPath,
      },
    });
    return { app, v, file, repoPath };
  }

  it("FIRST_SIGNER approval pins the signer, publishes the file and creates the patch", async () => {
    const { app, v, file, repoPath } = await held({ version: "26.01", holdReason: "FIRST_SIGNER", signerOrg: "Igor Pavlov", pins: null });
    await decidePackage(v.id, true, "admin@bank");

    expect(existsSync(file)).toBe(false);
    expect(readFileSync(repoAbsPath(repoDir, repoPath), "utf8")).toBe("installer 26.01");
    const after = await prisma.appVersion.findUniqueOrThrow({ where: { id: v.id }, include: { patch: true } });
    expect(after).toMatchObject({ verification: "VERIFIED", decidedBy: "admin@bank" });
    expect(after.availableAt!.getTime()).toBeGreaterThan(Date.now() + 47 * 3_600_000);
    expect(after.patch).toMatchObject({ kind: "THIRD_PARTY", externalId: "7zip.7zip@26.01", supersededById: null });
    expect((await prisma.app.findUniqueOrThrow({ where: { id: app.id } })).expectedPublisher).toBe("O=Igor Pavlov");
    const audit = await prisma.auditEvent.findFirstOrThrow({ where: { action: "package.approve" } });
    expect(audit.payload).toMatchObject({ signerOrg: "Igor Pavlov", pins: "O=Igor Pavlov", holdReason: "FIRST_SIGNER" });
    expect(audit.tenantId).toBeNull(); // trust decisions are platform actions: platform chain

    await expect(decidePackage(v.id, true, "admin@bank")).rejects.toThrow(/Only held/);
  });

  it("SIGNER_CHANGED approval appends to the pin list; HASH_DRIFT approval leaves pins alone", async () => {
    const a = await held({ version: "26.01", holdReason: "SIGNER_CHANGED", signerOrg: "Igor Pavlov Ltd", pins: "O=Igor Pavlov" });
    await decidePackage(a.v.id, true, "admin@bank");
    expect((await prisma.app.findUniqueOrThrow({ where: { id: a.app.id } })).expectedPublisher).toBe("O=Igor Pavlov; O=Igor Pavlov Ltd");

    const b = await held({ version: "26.02", holdReason: "HASH_DRIFT", signerOrg: "Igor Pavlov", pins: null, appId: a.app.id });
    await decidePackage(b.v.id, true, "admin@bank");
    expect((await prisma.app.findUniqueOrThrow({ where: { id: a.app.id } })).expectedPublisher).toBe("O=Igor Pavlov; O=Igor Pavlov Ltd");
    const patches = await prisma.patch.findMany({ include: { appVersion: true }, orderBy: { createdAt: "asc" } });
    expect(patches.map((p) => [p.appVersion!.version, p.supersededById === null])).toEqual([["26.01", false], ["26.02", true]]);
  });

  it("refuses to approve a held file that changed on disk", async () => {
    const { v, file } = await held({ version: "26.01", holdReason: "FIRST_SIGNER", signerOrg: "Igor Pavlov", pins: null });
    writeFileSync(file, "tampered");
    await expect(decidePackage(v.id, true, "admin@bank")).rejects.toThrow(/changed on disk/);
    expect((await prisma.appVersion.findUniqueOrThrow({ where: { id: v.id } })).verification).toBe("HELD");
    expect(existsSync(file)).toBe(true);
  });

  it("reject deletes the held file and records who rejected it", async () => {
    const { v, file } = await held({ version: "26.01", holdReason: "FIRST_SIGNER", signerOrg: "Igor Pavlov", pins: null });
    await decidePackage(v.id, false, "admin@bank");
    expect(existsSync(file)).toBe(false);
    expect(await prisma.appVersion.findUniqueOrThrow({ where: { id: v.id } })).toMatchObject({ verification: "REJECTED", rejectReason: "rejected by admin@bank" });
    expect(await prisma.patch.count()).toBe(0);
  });

  it("late approval of an OLDER version never supersedes the newer published one", async () => {
    const newer = await held({ version: "26.04", holdReason: "FIRST_SIGNER", signerOrg: "Igor Pavlov", pins: null });
    await decidePackage(newer.v.id, true, "admin@bank");
    const older = await held({ version: "26.01", holdReason: "SIGNER_CHANGED", signerOrg: "Igor Pavlov Ltd", pins: null, appId: newer.app.id });
    await decidePackage(older.v.id, true, "admin@bank");

    const newerPatch = await prisma.patch.findFirstOrThrow({ where: { appVersionId: newer.v.id } });
    const olderPatch = await prisma.patch.findFirstOrThrow({ where: { appVersionId: older.v.id } });
    expect(newerPatch.supersededById).toBeNull();
    expect(olderPatch.supersededById).toBe(newerPatch.id);
  });
});
