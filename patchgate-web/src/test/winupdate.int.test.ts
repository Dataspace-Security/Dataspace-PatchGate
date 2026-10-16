/**
 * Windows updates through PatchGate — DB integration (TEST_DATABASE_URL=…/patchgate_test_wu).
 * Network (Microsoft Update Catalog lookups, downloads) and signature verification are faked; everything
 * else (RLS-scoped transactions, catalog binding + DB triggers, applicability, quarantine, quota, audit
 * chains, repo publish) is real.
 */
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { copyFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { TENANT_A, TENANT_B, configureTestEnv, resetDb } from "./helpers";

const repoDir = mkdtempSync(join(tmpdir(), "pg-wu-int-"));
configureTestEnv({ REPO_DIR: repoDir, QUARANTINE_HOURS: "48" });

const { prisma } = await import("@/lib/db");
const { withTenant } = await import("@/lib/tenancy");
const { verifyAuditLog } = await import("@/lib/audit/service");
const { resultSchemas } = await import("@/lib/connector/protocol");
const hooks = await import("@/lib/winupdate/hooks");
const { fetchScanCab } = await import("@/lib/winupdate/cab");
const { processFile, processPendingFiles, winupdatePackageBySha256, WU_MAX_UPDATE_BYTES } = await import("@/lib/winupdate/files");
const { resolvePendingUpdates } = await import("@/lib/winupdate/resolve");
const { fetchWindowsUpdatesDue } = await import("@/lib/winupdate");
type CatalogLookup = import("@/lib/winupdate/catalog").CatalogLookup;

const fixtureDir = mkdtempSync(join(tmpdir(), "pg-wu-fx-"));
const bytes = (s: string) => Buffer.from(`microsoft-update-${s}`.repeat(50));
function fixture(name: string) {
  const b = bytes(name);
  const path = join(fixtureDir, name);
  writeFileSync(path, b);
  const sha1 = createHash("sha1").update(b).digest();
  const sha256 = createHash("sha256").update(b).digest();
  return { path, size: b.length, sha1: sha1.toString("hex"), sha256: sha256.toString("hex"), sha1b64: sha1.toString("base64"), sha256b64: sha256.toString("base64") };
}
const LCU = fixture("lcu");
const SSU = fixture("ssu");
const BAD = fixture("bad");
const OLD = fixture("old-build"); // a real-looking, Microsoft-signed file of ANOTHER (older) update

const U1 = "11111111-2222-3333-4444-555555555555"; // catalog: checkpoint (other KB) + LCU
const U2 = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"; // catalog: one file whose signature fails
const U3 = "99999999-8888-7777-6666-555555555555"; // not in the catalog
const wuUrl = (name: string) => `http://download.windowsupdate.com/c/msdownload/update/software/secu/2026/10/${name}`;
const tlsUrl = (name: string) => `https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2026/10/${name}`;
const MS = { ok: true as const, subject: "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" };
const LCU_NAME = `windows11.0-kb5099999-x64_${LCU.sha1}.msu`;
const SSU_NAME = `windows11.0-kb5099990-x64_${SSU.sha1}.msu`;
const OLD_NAME = `windows11.0-kb5011111-x64_${OLD.sha1}.msu`;

/** What the Microsoft Update Catalog says (authoritative). */
const CATALOG: Record<string, CatalogLookup> = {
  [U1]: {
    found: true,
    updateId: U1,
    title: "2026-10 Cumulative Update for Windows 11 (KB5099999)",
    details: { title: "2026-10 Cumulative Update for Windows 11 (KB5099999)", kb: "KB5099999", msrcSeverity: "Critical", classification: "Security Updates" },
    files: [
      { url: wuUrl(LCU_NAME), fileName: LCU_NAME, digest: LCU.sha1b64, sha256: LCU.sha256b64, languages: "" },
      { url: wuUrl(SSU_NAME), fileName: SSU_NAME, digest: SSU.sha1b64, sha256: SSU.sha256b64, languages: "" },
    ],
  },
  [U2]: {
    found: true,
    updateId: U2,
    title: "Bad (KB5088888)",
    details: { title: "Bad (KB5088888)", kb: "KB5088888", msrcSeverity: "Important", classification: "Security Updates" },
    files: [{ url: wuUrl(`x-kb5088888_${BAD.sha1}.cab`), fileName: "x", digest: BAD.sha1b64, sha256: BAD.sha256b64, languages: "" }],
  },
};
const lookups: string[] = [];
const fakeCatalog = (overrides: Record<string, CatalogLookup | Error> = {}) => ({
  lookup: async (id: string): Promise<CatalogLookup> => {
    lookups.push(id);
    const o = overrides[id];
    if (o instanceof Error) throw o;
    return o ?? CATALOG[id] ?? { found: false };
  },
});

const byUrl = new Map<string, { path: string; size: number; sha256: string }>();
const fakeFiles = (sigFor: (p: string) => typeof MS | { ok: false; reason: string } = () => MS) => ({
  download: async (url: string, dest: string, maxBytes: number) => {
    const f = [...byUrl.entries()].find(([k]) => url.endsWith(k))?.[1];
    if (!f) throw new Error("HTTP 503 from catalog.s.download.windowsupdate.com");
    if (f.size > maxBytes) throw new Error("Download exceeds size limit");
    await copyFile(f.path, dest);
    return { sha256: f.sha256, size: f.size };
  },
  readSignature: async (p: string) => sigFor(p),
});

/** A (possibly compromised) PC report: everything except the GUIDs is attacker-controlled. */
function scanResult(agentId: string, evil = false) {
  return resultSchemas.WU_SCAN.parse({
    agents: [
      {
        agentId,
        updates: [
          {
            updateId: U1.toUpperCase(),
            revision: 200,
            kb: evil ? "KB5011111" : "KB5099999",
            title: evil ? "Harmless optional update" : "2026-10 Cumulative Update for Windows 11",
            msrcSeverity: evil ? "Low" : "Critical",
            classification: "Security Updates",
            files: [
              // older Microsoft-signed build without/with another KB: must never be bound to U1
              { url: wuUrl(OLD_NAME), name: "old", size: OLD.size, sha1: OLD.sha1, sha256: OLD.sha256 },
              { url: wuUrl(`nokb_${OLD.sha1}.msu`), name: "nokb", size: 0, sha1: null, sha256: null },
            ],
          },
          { updateId: U2, revision: 1, kb: "KB5088888", title: "Bad", msrcSeverity: "Important", classification: "Security Updates", files: [] },
          { updateId: U3, revision: 1, kb: null, title: "Evil", msrcSeverity: null, classification: null, files: [{ url: `https://evil.example/c/msdownload/update/software/secu/x_${BAD.sha1}.cab`, name: "e", size: 0, sha1: null, sha256: null }] },
        ],
      },
      { agentId: "agent-b-0001", updates: [{ updateId: U1, revision: 200, kb: "KB5099999", title: "x", msrcSeverity: null, classification: null, files: [] }] },
      { agentId: "agent-a-0002", error: "Windows Update service is disabled" },
    ],
  });
}

let connectorId = "";
let epA = "";

beforeEach(async () => {
  await prisma.$executeRawUnsafe(`DELETE FROM "WinUpdateFile"`);
  await prisma.$executeRawUnsafe(`DELETE FROM "WinUpdate"`);
  await prisma.$executeRawUnsafe(`DELETE FROM "WsusScanCab"`);
  await resetDb(prisma);
  rmSync(join(repoDir, "winupdate"), { recursive: true, force: true });
  lookups.length = 0;
  byUrl.clear();
  byUrl.set(`_${SSU.sha1}.msu`, SSU);
  byUrl.set(`_${LCU.sha1}.msu`, LCU);
  byUrl.set(`_${BAD.sha1}.cab`, BAD);
  byUrl.set(`_${OLD.sha1}.msu`, OLD);
  const c = await prisma.connector.create({ data: { tenantId: TENANT_A, name: "HO", publicKey: "k".repeat(43) + "=" } });
  connectorId = c.id;
  epA = (await prisma.endpoint.create({ data: { tenantId: TENANT_A, tacticalAgentId: "agent-a-0001", hostname: "pc-a1", connectorId } })).id;
  await prisma.endpoint.create({ data: { tenantId: TENANT_A, tacticalAgentId: "agent-a-0002", hostname: "pc-a2", connectorId } });
  await prisma.endpoint.create({ data: { tenantId: TENANT_B, tacticalAgentId: "agent-b-0001", hostname: "pc-b1" } });
});

afterAll(async () => {
  await prisma.$disconnect();
  rmSync(repoDir, { recursive: true, force: true });
  rmSync(fixtureDir, { recursive: true, force: true });
});

const ctx = () => ({ tenantId: TENANT_A, connectorId, jobId: "job-scan-1" });
const ingest = (evil = false) => withTenant(TENANT_A, (tx) => hooks.handleWuScanResult(tx, ctx(), scanResult("agent-a-0001", evil)));
const plan = (tenantId = TENANT_A, patchIds: string[] = []) =>
  withTenant(tenantId, (tx) => hooks.planWuInstall(tx, { tenantId, endpointId: epA, patchIds, rebootPolicy: "IF_REQUIRED" }));
const allPatchIds = async () => (await prisma.patch.findMany({ where: { externalId: { in: [U1, U2, U3] } } })).map((p) => p.id);
const releaseQuarantine = () => prisma.winUpdateFile.updateMany({ where: { verification: "VERIFIED" }, data: { availableAt: new Date(Date.now() - 1000) } });

describe("WU_SCAN ingestion (PC reports say WHICH updates apply, nothing else)", () => {
  it("stores GUIDs + applicability only; reported title/KB/severity/files are ignored", async () => {
    await ingest(true);
    const patch = await prisma.patch.findUniqueOrThrow({ where: { externalId: U1 } });
    expect(patch).toMatchObject({ kind: "WINDOWS", kb: null, severity: "UNSPECIFIED", classification: null, title: expect.stringContaining("pending Microsoft Update Catalog") });
    expect(await prisma.winUpdate.findUniqueOrThrow({ where: { id: U1 } })).toMatchObject({ catalogState: "PENDING", kb: null, firstTenantId: TENANT_A });
    expect(await prisma.winUpdateFile.count()).toBe(0);

    const states = await prisma.endpointPatchState.findMany({ where: { endpointId: epA }, include: { patch: true } });
    expect(states.map((s) => [s.patch.externalId, s.status, s.tenantId]).sort()).toEqual([[U1, "NEEDED", TENANT_A], [U2, "NEEDED", TENANT_A], [U3, "NEEDED", TENANT_A]].sort());
    expect(await prisma.endpointPatchState.count({ where: { tenantId: TENANT_B } })).toBe(0);
    const a2 = await prisma.endpoint.findUniqueOrThrow({ where: { tacticalAgentId: "agent-a-0002" } });
    expect(a2.lastWuScanError).toContain("disabled");
    const ev = await prisma.auditEvent.findFirstOrThrow({ where: { tenantId: TENANT_A, action: "winupdate.scan_ingested" } });
    expect(ev.payload).toMatchObject({ newUpdates: 3, reportedFilesIgnored: 3 });

    // Re-ingest is idempotent; an update no longer offered becomes NOT_APPLICABLE
    await ingest();
    expect(await prisma.winUpdate.count()).toBe(3);
    const second = resultSchemas.WU_SCAN.parse({ agents: [{ agentId: "agent-a-0001", updates: [] }] });
    await withTenant(TENANT_A, (tx) => hooks.handleWuScanResult(tx, { ...ctx(), jobId: "job-scan-2" }, second));
    expect((await prisma.endpointPatchState.findMany({ where: { endpointId: epA } })).every((s) => s.status === "NOT_APPLICABLE")).toBe(true);
    expect((await verifyAuditLog(TENANT_A)).valid).toBe(true);
  });
});

describe("Microsoft Update Catalog binding (finding #2: authoritative update → files)", () => {
  it("binds metadata + files from the catalog once; later reports and DB writes cannot change them", async () => {
    await ingest(true); // a compromised PC of bank A reports U1 with an older build + a file without KB
    expect(await resolvePendingUpdates(fakeCatalog())).toEqual({ resolved: 2, unresolvable: 0, retry: 1 });

    const patch = await prisma.patch.findUniqueOrThrow({ where: { externalId: U1 } });
    expect(patch).toMatchObject({ kb: "KB5099999", severity: "CRITICAL", classification: "Security Updates", title: "2026-10 Cumulative Update for Windows 11 (KB5099999)" });
    const files = await prisma.winUpdateFile.findMany({ where: { updateId: U1 }, orderBy: { ordinal: "asc" } });
    // only the catalog's files, checkpoint (other KB) first, with BOTH catalog digests
    expect(files.map((f) => [f.source, f.url, f.sha1, f.expectedSha256])).toEqual([
      ["CATALOG", tlsUrl(SSU_NAME), SSU.sha1, SSU.sha256],
      ["CATALOG", tlsUrl(LCU_NAME), LCU.sha1, LCU.sha256],
    ]);
    expect(await prisma.winUpdateFile.count({ where: { sha1: OLD.sha1 } })).toBe(0);

    // bank B's (or a compromised) later report changes nothing
    await ingest(true);
    await withTenant(TENANT_B, (tx) => hooks.handleWuScanResult(tx, { tenantId: TENANT_B, connectorId: "c-b", jobId: "job-b" }, resultSchemas.WU_SCAN.parse({ agents: [{ agentId: "agent-b-0001", updates: [{ updateId: U1, revision: 999, kb: "KB1234567", title: "evil", msrcSeverity: "Low", classification: null, files: [] }] }] })));
    expect(await prisma.patch.findUniqueOrThrow({ where: { externalId: U1 } })).toMatchObject({ kb: "KB5099999", severity: "CRITICAL" });
    expect(await prisma.winUpdateFile.count({ where: { updateId: U1 } })).toBe(2);

    // DB triggers: resolved metadata is immutable, sealed bindings take no new / changed files
    await expect(prisma.winUpdate.update({ where: { id: U1 }, data: { title: "evil" } })).rejects.toThrow(/immutable/);
    await expect(prisma.winUpdateFile.create({ data: { updateId: U1, url: tlsUrl(OLD_NAME), name: OLD_NAME, kind: "msu", sha1: OLD.sha1, source: "CATALOG" } })).rejects.toThrow(/sealed/);
    await expect(prisma.winUpdateFile.create({ data: { updateId: U3, url: tlsUrl(OLD_NAME), name: OLD_NAME, kind: "msu", sha1: OLD.sha1 } })).rejects.toThrow(/only Microsoft Update Catalog/);
    await expect(prisma.winUpdateFile.update({ where: { id: files[1].id }, data: { url: tlsUrl(OLD_NAME), sha1: OLD.sha1 } })).rejects.toThrow(/immutable/);

    const ev = await prisma.auditEvent.findFirstOrThrow({ where: { tenantId: null, action: "winupdate.update.resolved", entityId: U1 } });
    expect(ev.payload).toMatchObject({ kb: "KB5099999" });
    expect((await verifyAuditLog(null)).valid).toBe(true);
  });

  it("not in the catalog: retried, then UNRESOLVABLE (undeliverable, audited)", async () => {
    await ingest();
    const t = new Date();
    await resolvePendingUpdates(fakeCatalog(), t);
    const u3 = await prisma.winUpdate.findUniqueOrThrow({ where: { id: U3 } });
    expect(u3).toMatchObject({ catalogState: "PENDING", resolveAttempts: 1, resolveError: expect.stringContaining("not found") });
    expect(u3.nextResolveAt.getTime()).toBeGreaterThan(t.getTime());
    expect(await resolvePendingUpdates(fakeCatalog(), t)).toEqual({ resolved: 0, unresolvable: 0, retry: 0 }); // not due yet
    await resolvePendingUpdates(fakeCatalog(), new Date(t.getTime() + 2 * 3_600_000));
    await resolvePendingUpdates(fakeCatalog(), new Date(t.getTime() + 10 * 3_600_000));
    expect(await prisma.winUpdate.findUniqueOrThrow({ where: { id: U3 } })).toMatchObject({ catalogState: "UNRESOLVABLE" });
    expect(await prisma.auditEvent.count({ where: { action: "winupdate.update.unresolvable", entityId: U3 } })).toBe(1);
  });

  it("a catalog binding Microsoft cannot deliver (language set / exe) seals the update as UNRESOLVABLE", async () => {
    await ingest();
    const f = (CATALOG[U1] as Extract<CatalogLookup, { found: true }>).files;
    const langs: CatalogLookup = { ...(CATALOG[U1] as Extract<CatalogLookup, { found: true }>), files: [{ ...f[0], languages: "de" }, { ...f[1], languages: "fr" }] };
    await resolvePendingUpdates(fakeCatalog({ [U1]: langs, [U2]: new Error("HTTP 503 from www.catalog.update.microsoft.com") }));
    expect(await prisma.winUpdate.findUniqueOrThrow({ where: { id: U1 } })).toMatchObject({ catalogState: "UNRESOLVABLE", kb: "KB5099999", resolveError: expect.stringContaining("language") });
    expect(await prisma.winUpdate.findUniqueOrThrow({ where: { id: U2 } })).toMatchObject({ catalogState: "PENDING", resolveError: expect.stringContaining("503") });
    expect(await prisma.winUpdateFile.count({ where: { updateId: U1 } })).toBe(0);
  });

  it("re-validates legacy PC-reported bindings: keeps a verified file that matches the catalog, removes the rest", async () => {
    await ingest();
    // Legacy rows from before the fix (REPORTED; inserted bypassing the new triggers like the old code did)
    mkdirSync(join(repoDir, "winupdate", U1), { recursive: true });
    writeFileSync(join(repoDir, "winupdate", U1, LCU_NAME), readFileSync(LCU.path));
    writeFileSync(join(repoDir, "winupdate", U1, OLD_NAME), readFileSync(OLD.path));
    await prisma.$transaction(async (tx) => {
      await tx.$executeRawUnsafe(`SET LOCAL session_replication_role = replica`);
      const row = (id: string, name: string, f: typeof LCU) =>
        `('${id}', '${U1}', '${tlsUrl(name)}', '${name}', 'msu', 0, '${f.sha1}', '${f.sha256}', ${f.size}, 'VERIFIED', 'REPORTED', 'winupdate/${U1}/${name}', now() - interval '1 day', now())`;
      await tx.$executeRawUnsafe(
        `INSERT INTO "WinUpdateFile" ("id","updateId","url","name","kind","ordinal","sha1","sha256","sizeBytes","verification","source","repoPath","availableAt","updatedAt") VALUES ${row("legacy-lcu", LCU_NAME, LCU)}, ${row("legacy-old", OLD_NAME, OLD)}`,
      );
    });
    // before re-validation nothing reported is installable or served
    expect(await plan(TENANT_A, await allPatchIds())).toBeNull(); // updates PENDING → wait
    expect(await winupdatePackageBySha256(prisma, OLD.sha256)).toBeNull();

    await resolvePendingUpdates(fakeCatalog());
    const rows = await prisma.winUpdateFile.findMany({ where: { updateId: U1 }, orderBy: { ordinal: "asc" } });
    expect(rows.map((r) => [r.id === "legacy-lcu" ? "kept" : r.id === "legacy-old" ? "OLD" : "new", r.source, r.verification])).toEqual([
      ["new", "CATALOG", "PENDING"],
      ["kept", "CATALOG", "VERIFIED"],
    ]);
    expect(existsSync(join(repoDir, "winupdate", U1, OLD_NAME))).toBe(false);
    expect(existsSync(join(repoDir, "winupdate", U1, LCU_NAME))).toBe(true);
    expect((await prisma.auditEvent.findFirstOrThrow({ where: { action: "winupdate.update.resolved", entityId: U1 } })).payload).toMatchObject({ keptVerified: 1, removedReportedFiles: 1 });
  });
});

describe("file pipeline → plan → install result", () => {
  it("verifies, quarantines, plans in catalog order, records install outcome + reboot", async () => {
    await ingest(true);
    const patchIds = await allPatchIds();
    expect(await plan(TENANT_A, patchIds)).toBeNull(); // catalog lookup pending → wait
    await resolvePendingUpdates(fakeCatalog({ [U3]: { found: false } }));
    const t0 = new Date();
    await prisma.winUpdate.update({ where: { id: U3 }, data: { catalogState: "UNRESOLVABLE", resolveError: "not published" } });
    expect(await plan(TENANT_A, patchIds)).toBeNull(); // files pending → wait

    const r = await processPendingFiles(fakeFiles((p) => (bytesOf(p) === BAD.sha256 ? { ok: false, reason: "signature NotSigned" } : MS)), t0);
    expect(r).toMatchObject({ verified: 2, rejected: 1, retry: 0, deferred: 0, quotaExceeded: false });
    const lcu = await prisma.winUpdateFile.findFirstOrThrow({ where: { sha1: LCU.sha1 } });
    expect(lcu).toMatchObject({ verification: "VERIFIED", sha256: LCU.sha256, repoPath: `winupdate/${U1}/${LCU_NAME}` });
    expect(existsSync(join(repoDir, ...lcu.repoPath!.split("/")))).toBe(true);
    expect(lcu.availableAt!.getTime()).toBeGreaterThan(t0.getTime() + 47 * 3_600_000);
    expect(await prisma.winUpdateFile.findFirstOrThrow({ where: { updateId: U2 } })).toMatchObject({ verification: "REJECTED", rejectReason: "signature NotSigned" });
    expect(await plan(TENANT_A, patchIds)).toBeNull(); // quarantined → wait
    expect(await winupdatePackageBySha256(prisma, LCU.sha256)).toBeNull();

    await releaseQuarantine();
    const p = await plan(TENANT_A, patchIds);
    expect(p).not.toBeNull();
    expect(p!.payload.updates.map((u) => u.updateId)).toEqual([U1]); // U2 rejected file, U3 unresolvable
    expect(p!.payload.updates[0].kb).toBe("KB5099999");
    expect(p!.payload.updates[0].files.map((f) => f.sha256)).toEqual([SSU.sha256, LCU.sha256]);
    expect(p!.cacheNeeds).toHaveLength(2);
    expect(await winupdatePackageBySha256(prisma, LCU.sha256)).toMatchObject({ size: LCU.size });
    expect(await plan(TENANT_B, patchIds)).toBeNull(); // other bank cannot plan bank A's endpoint

    const job = await prisma.connectorJob.create({
      data: { tenantId: TENANT_A, connectorId, type: "WU_INSTALL", payload: { agentId: "agent-a-0001", ...p!.payload }, signature: "sig", expiresAt: new Date(Date.now() + 3_600_000) },
    });
    await withTenant(TENANT_A, (tx) =>
      hooks.handleWuInstallResult(tx, { tenantId: TENANT_A, connectorId, jobId: job.id, deploymentId: null }, { outcome: "INSTALLED", installed: [U1.toUpperCase(), U3], failed: [], rebootRequired: true }),
    );
    const states = await prisma.endpointPatchState.findMany({ where: { endpointId: epA }, include: { patch: true } });
    expect(states.find((s) => s.patch.externalId === U1)?.status).toBe("INSTALLED");
    expect(states.find((s) => s.patch.externalId === U3)?.status).toBe("NEEDED");
    expect((await prisma.endpoint.findUniqueOrThrow({ where: { id: epA } })).rebootRequired).toBe(true);
    await withTenant(TENANT_A, (tx) =>
      hooks.handleWuInstallResult(tx, { tenantId: TENANT_A, connectorId, jobId: job.id, deploymentId: null }, { outcome: "PARTIAL", installed: [], failed: [{ updateId: U1, error: "installer exit 0x80070643" }], rebootRequired: false }),
    );
    expect((await prisma.endpointPatchState.findFirstOrThrow({ where: { endpointId: epA, patch: { externalId: U1 } } })).status).toBe("FAILED");
    expect((await verifyAuditLog(TENANT_A)).valid).toBe(true);
    expect((await verifyAuditLog(null)).valid).toBe(true);
  });

  it("transient download errors back off; permanent ones reject", async () => {
    await ingest();
    await resolvePendingUpdates(fakeCatalog());
    byUrl.clear(); // every download → HTTP 503
    const now = new Date();
    expect(await processPendingFiles(fakeFiles(), now)).toMatchObject({ verified: 0, rejected: 0, retry: 3 });
    const f = await prisma.winUpdateFile.findFirstOrThrow({ where: { sha1: LCU.sha1 } });
    expect(f.attempts).toBe(1);
    expect(f.nextAttemptAt.getTime()).toBeGreaterThan(now.getTime() + 59 * 60_000);
    expect(await processPendingFiles(fakeFiles(), now)).toMatchObject({ verified: 0, rejected: 0, retry: 0 });
    const notFound = { download: async () => { throw new Error("HTTP 404 from catalog.s.download.windowsupdate.com"); }, readSignature: async () => MS };
    expect(await processPendingFiles(notFound, new Date(now.getTime() + 2 * 3_600_000))).toMatchObject({ verified: 0, rejected: 3, retry: 0 });
  });
});

describe("repository quota + byte budgets (finding #9)", () => {
  it("over quota: nothing is downloaded, files wait, the transition is audited; under quota it resumes", async () => {
    await ingest();
    await resolvePendingUpdates(fakeCatalog());
    mkdirSync(join(repoDir, "winupdate"), { recursive: true });
    writeFileSync(join(repoDir, "winupdate", "filler.bin"), Buffer.alloc(4096));
    const over = await processPendingFiles(fakeFiles(), new Date(), { quotaBytes: 1024 });
    expect(over).toMatchObject({ verified: 0, rejected: 0, quotaExceeded: true });
    expect(await prisma.winUpdateFile.count({ where: { verification: "PENDING" } })).toBe(3);
    expect(await prisma.fetchRun.findFirstOrThrow({ where: { source: "repo-quota" }, orderBy: { startedAt: "desc" } })).toMatchObject({ ok: false, message: expect.stringContaining("QUOTA EXCEEDED") });
    await processPendingFiles(fakeFiles(), new Date(), { quotaBytes: 1024 }); // still exceeded: audited once
    expect(await prisma.auditEvent.count({ where: { tenantId: null, action: "repo.quota_exceeded" } })).toBe(1);

    const ok = await processPendingFiles(fakeFiles(), new Date(), { quotaBytes: 1024 ** 3 });
    expect(ok).toMatchObject({ verified: 3, rejected: 0, quotaExceeded: false });
    expect(await prisma.auditEvent.count({ where: { tenantId: null, action: "repo.quota_ok" } })).toBe(1);
    rmSync(join(repoDir, "winupdate", "filler.bin"), { force: true });
  });

  it("per-run budget defers (not rejects); per-update budget rejects", async () => {
    await ingest();
    await resolvePendingUpdates(fakeCatalog());
    const now = new Date();
    const r = await processPendingFiles(fakeFiles(), now, { maxBytes: LCU.size + 10 });
    expect(r).toMatchObject({ verified: 1, deferred: 2, rejected: 0 });
    const deferred = await prisma.winUpdateFile.findFirstOrThrow({ where: { verification: "PENDING" } });
    expect(deferred).toMatchObject({ attempts: 0, lastError: expect.stringContaining("budget") });
    expect(deferred.nextAttemptAt.getTime()).toBeGreaterThan(now.getTime());

    // the update already holds its full byte budget → its remaining file is rejected (update undeliverable)
    const verified = await prisma.winUpdateFile.findFirstOrThrow({ where: { verification: "VERIFIED" } });
    await prisma.winUpdateFile.update({ where: { id: verified.id }, data: { sizeBytes: BigInt(WU_MAX_UPDATE_BYTES) } });
    const pending = await prisma.winUpdateFile.findFirstOrThrow({ where: { updateId: verified.updateId, verification: "PENDING" } });
    expect(await processFile(pending, fakeFiles(), now)).toBe("rejected");
    expect(await prisma.winUpdateFile.findUniqueOrThrow({ where: { id: pending.id } })).toMatchObject({ rejectReason: expect.stringContaining("per-update") });
  });
});

function bytesOf(p: string): string {
  return createHash("sha256").update(readFileSync(p)).digest("hex");
}

describe("scan catalog (wsusscn2.cab)", () => {
  const cab = fixture("wsusscn2");
  const v = { etag: '"abc:0"', lastModified: "Wed, 14 Oct 2026 09:33:12 GMT", size: cab.size };
  const deps = (sig = MS as typeof MS | { ok: false; reason: string }, validators = v) => ({
    probe: async () => validators,
    download: async (_u: string, dest: string) => {
      await copyFile(cab.path, dest);
      return { sha256: cab.sha256, size: cab.size };
    },
    readSignature: async () => sig,
  });

  it("publishes a Microsoft-signed cab once, offers it to WU_SCAN jobs, skips unchanged", async () => {
    expect(await withTenant(TENANT_A, (tx) => hooks.wuScanCab(tx))).toBeNull();
    expect(await fetchScanCab(deps())).toMatchObject({ status: "published", sha256: cab.sha256 });
    const pkg = await withTenant(TENANT_A, (tx) => hooks.wuScanCab(tx));
    expect(pkg).toMatchObject({ kind: "wsusscan", sha256: cab.sha256, size: cab.size, publisher: "O=Microsoft Corporation" });
    expect(existsSync(join(repoDir, ...pkg!.repoPath.split("/")))).toBe(true);
    expect(await fetchScanCab(deps())).toMatchObject({ status: "up-to-date" });
    expect(await winupdatePackageBySha256(prisma, cab.sha256)).toMatchObject({ repoPath: pkg!.repoPath });
    // daily gate in the fetch loop; the catalog lookup step runs every time
    const due = await fetchWindowsUpdatesDue(new Date(), { cab: deps(), files: fakeFiles(), resolve: fakeCatalog() });
    expect(due.scanCab).toBe("not due");
    expect(due.catalog).toEqual({ resolved: 0, unresolvable: 0, retry: 0 });
  });

  it("rejects a cab not signed by Microsoft and does not retry the same version", async () => {
    expect(await fetchScanCab(deps({ ok: true, subject: "CN=Contoso, O=Contoso Ltd" }))).toMatchObject({ status: "rejected", reason: expect.stringContaining("publisher") });
    expect(await fetchScanCab(deps())).toMatchObject({ status: "rejected", reason: expect.stringContaining("unchanged since rejection") });
    expect(await withTenant(TENANT_A, (tx) => hooks.wuScanCab(tx))).toBeNull();
    expect((await verifyAuditLog(null)).valid).toBe(true);
  });
});
