/**
 * Package entitlement (bank B can never pull bank A's package), path safety, and the audit relay
 * (a bank's own chain only).
 */
import { mkdtempSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { TENANT_A, TENANT_B, configureTestEnv, resetDb } from "./helpers";
import { enrollBody, makeConnectorKey, sessionUserOf, writeRepoFile } from "./connector-helpers";

const repoDir = mkdtempSync(join(tmpdir(), "pg-conn-pkg-"));
configureTestEnv({ REPO_DIR: repoDir, LOG_LEVEL: "error" });
const { prisma } = await import("@/lib/db");
const { withTenant } = await import("@/lib/tenancy");
const { createEnrollmentCode } = await import("@/lib/connector/admin");
const { redeemEnrollment } = await import("@/lib/connector/enroll");
const { enqueueJob } = await import("@/lib/connector/queue");
const { resolvePackageDownload, servableFile } = await import("@/lib/connector/packages");
const { auditPage, parseAuditQuery } = await import("@/lib/connector/audit-relay");
const { appendAudit } = await import("@/lib/audit/service");
const { auditRelayResponseSchema, sha256Hex } = await import("@/lib/connector/protocol");
const { checkSiemStream } = await import("@/lib/siem/verify-stream");

beforeEach(() => resetDb(prisma));
afterAll(async () => {
  await prisma.$disconnect();
  rmSync(repoDir, { recursive: true, force: true });
});

async function connector(tenantId: string, name = "HQ") {
  const admin = sessionUserOf(await prisma.user.upsert({ where: { upn: "admin@pg" }, update: {}, create: { upn: "admin@pg", name: "A", role: "ADMIN" } }));
  const { code } = await createEnrollmentCode(admin, { tenantId, name });
  const r = await redeemEnrollment(enrollBody(code, makeConnectorKey()));
  return { id: r.connectorId, tenantId, name, maxConcurrentInstalls: 50, bandwidthLimitMbps: null };
}

async function appVersionFor(file: { sha256: string; repoPath: string }, wingetId: string) {
  const app = await prisma.app.create({ data: { wingetId, displayName: wingetId, inventoryMatch: wingetId, expectedPublisher: "O=Vendor", allowedDomains: [] } });
  const v = await prisma.appVersion.create({
    data: { appId: app.id, version: "1.0", installerUrl: "https://vendor.example/x.msi", sha256: file.sha256, silentArgs: "", verification: "VERIFIED", repoPath: file.repoPath, availableAt: new Date(0) },
  });
  return { app, v };
}

describe("package entitlement", () => {
  it("serves a package only to banks that enabled the app (or approved it in a change request)", async () => {
    const a = await connector(TENANT_A);
    const b = await connector(TENANT_B);
    const file = writeRepoFile(repoDir, "pkgs/vendor/1.0/app.msi", "bank-A-only app bytes");
    const { app } = await appVersionFor(file, "Vendor.App");
    await prisma.tenantApp.create({ data: { tenantId: TENANT_A, appId: app.id, enabledBy: "admin@pg" } });

    const dl = await resolvePackageDownload(a, file.sha256);
    expect(dl).toMatchObject({ size: file.size, repoPath: file.repoPath });
    await expect(resolvePackageDownload(b, file.sha256)).rejects.toMatchObject({ status: 404 });
    await expect(resolvePackageDownload(a, "0".repeat(64))).rejects.toMatchObject({ status: 404 });
    await expect(resolvePackageDownload(a, "../../etc/passwd")).rejects.toMatchObject({ status: 404 });
    // the download is audited on the bank's chain
    expect(await prisma.auditEvent.findFirstOrThrow({ where: { action: "connector.package_downloaded" } })).toMatchObject({ tenantId: TENANT_A, entityId: file.sha256 });
  });

  it("serves verified Tactical agent builds to every bank, but not unapproved ones", async () => {
    const b = await connector(TENANT_B);
    const ok = writeRepoFile(repoDir, "tactical/agent/2.12.0/tacticalagent-v2.12.0-windows-amd64.exe", "agent bytes");
    await prisma.mirroredRelease.create({
      data: { component: "TACTICAL_AGENT", version: "2.12.0", assetName: "tacticalagent-v2.12.0-windows-amd64.exe", sourceUrl: "https://github.com/x", sha256: ok.sha256, sizeBytes: BigInt(ok.size), repoPath: ok.repoPath, verification: "VERIFIED" },
    });
    const pending = writeRepoFile(repoDir, "tactical/agent/2.13.0/tacticalagent-v2.13.0-windows-amd64.exe", "unapproved agent");
    await prisma.mirroredRelease.create({
      data: { component: "TACTICAL_AGENT", version: "2.13.0", assetName: "tacticalagent-v2.13.0-windows-amd64.exe", sourceUrl: "https://github.com/x", sha256: pending.sha256, sizeBytes: BigInt(pending.size), repoPath: pending.repoPath, verification: "PENDING" },
    });
    await expect(resolvePackageDownload(b, ok.sha256)).resolves.toMatchObject({ size: ok.size });
    await expect(resolvePackageDownload(b, pending.sha256)).rejects.toMatchObject({ status: 404 });
  });

  it("serves winupdate files only to the connector the winupdate pipeline handed them to", async () => {
    const a = await connector(TENANT_A);
    const b = await connector(TENANT_B);
    const cab = writeRepoFile(repoDir, "winupdate/scan/wsusscn2.cab", "signed offline scan catalog");
    await withTenant(TENANT_A, (tx) =>
      enqueueJob(tx, {
        tenantId: TENANT_A,
        connectorId: a.id,
        type: "CACHE_PACKAGE",
        payload: { package: { kind: "wsusscan", wingetId: "Microsoft.WsusScan", version: "2026.10", sha256: cab.sha256, size: cab.size, repoPath: cab.repoPath, publisher: "", switches: "" } },
        expiresAt: new Date(Date.now() + 3_600_000),
      }),
    );
    await expect(resolvePackageDownload(a, cab.sha256)).resolves.toMatchObject({ repoPath: cab.repoPath });
    await expect(resolvePackageDownload(b, cab.sha256)).rejects.toMatchObject({ status: 404 });
  });

  it("never resolves outside pkgs/, tactical/, winupdate/ or through a symlink out of the repository", async () => {
    await expect(servableFile(repoDir, ".keys/job-signing-key.pem")).rejects.toMatchObject({ status: 404 });
    await expect(servableFile(repoDir, "pkgs/../.keys/x")).rejects.toMatchObject({ status: 404 });
    await expect(servableFile(repoDir, "other/file.bin")).rejects.toMatchObject({ status: 404 });
    const outside = mkdtempSync(join(tmpdir(), "pg-outside-"));
    writeRepoFile(outside, "secret.txt", "secret");
    let linked = false;
    try {
      symlinkSync(outside, join(repoDir, "pkgs", "escape"), "junction");
      linked = true;
    } catch {
      // symlinks may be unavailable for this account; the containment check is still covered above
    }
    if (linked) await expect(servableFile(repoDir, "pkgs/escape/secret.txt")).rejects.toMatchObject({ status: 404 });
    rmSync(outside, { recursive: true, force: true });
    expect(sha256Hex("x")).toHaveLength(64);
  });
});

describe("audit relay", () => {
  it("pages the bank's OWN chain only, with strictly increasing decimal seq", async () => {
    const a = await connector(TENANT_A);
    await appendAudit({ tenantId: TENANT_B, actor: "x", action: "bank_b.secret", entity: "T", entityId: "1" });
    await appendAudit({ actor: "x", action: "platform.secret", entity: "T", entityId: "2" });
    for (let i = 0; i < 3; i++) await appendAudit({ tenantId: TENANT_A, actor: "x", action: `bank_a.${i}`, entity: "T", entityId: String(i) });

    const page1 = await auditPage(a, BigInt(0), 2);
    const all = await auditPage(a, BigInt(0), 500);
    expect(all.records.every((r) => r.action.startsWith("bank_a.") || r.action.startsWith("connector."))).toBe(true);
    expect(all.records.some((r) => r.action === "bank_b.secret" || r.action === "platform.secret")).toBe(false);
    const seqs = all.records.map((r) => BigInt(r.seq));
    expect(seqs.every((s, i) => i === 0 || s > seqs[i - 1])).toBe(true);
    expect(page1.records).toHaveLength(2);
    const page2 = await auditPage(a, BigInt(page1.records[1].seq), 500);
    expect(page2.records[0].seq).toBe(all.records[2].seq);
    expect(all.head).toEqual({ seq: all.records[all.records.length - 1].seq, hash: all.records[all.records.length - 1].hash });

    expect(parseAuditQuery(new URL("https://x/api/connector/v1/audit?after=12&limit=900"))).toEqual({ after: BigInt(12), limit: 500 });
    expect(() => parseAuditQuery(new URL("https://x/api/connector/v1/audit?after=-1"))).toThrow();
    expect(() => parseAuditQuery(new URL("https://x/api/connector/v1/audit?after=1&limit=abc"))).toThrow();
  });

  it("carries each record's prevHash (bank chain, not the global seq order) so SIEM chain rules work on relayed records", async () => {
    const a = await connector(TENANT_A);
    for (let i = 0; i < 3; i++) {
      await appendAudit({ tenantId: TENANT_A, actor: "x", action: `bank_a.${i}`, entity: "T", entityId: String(i) });
      // interleaved events of another chain must not appear in bank A's prevHash links
      await appendAudit({ tenantId: TENANT_B, actor: "x", action: `bank_b.${i}`, entity: "T", entityId: String(i) });
    }
    const page = await auditPage(a, BigInt(0), 500);
    expect(auditRelayResponseSchema.safeParse(JSON.parse(JSON.stringify(page))).success).toBe(true);
    const stored = await prisma.auditEvent.findMany({ where: { tenantId: TENANT_A }, orderBy: { seq: "asc" } });
    expect(page.records.map((r) => r.prevHash)).toEqual(stored.map((e) => e.prevHash));
    for (let i = 1; i < page.records.length; i++) expect(page.records[i].prevHash).toBe(page.records[i - 1].hash);
    const asSiem = page.records.map((r) => ({ msgId: "AUDIT" as const, seq: Number(r.seq), hash: r.hash, prevHash: r.prevHash ?? undefined }));
    expect(checkSiemStream(asSiem)).toEqual([]);
    // a record withheld from the relay shows up as a chain break in the SIEM
    expect(checkSiemStream(asSiem.filter((_, i) => i !== 1))).toMatchObject([{ kind: "chain-break" }]);
    // older connectors (schema without prevHash) still parse a page without it
    expect(auditRelayResponseSchema.safeParse({ records: [{ ...page.records[0], prevHash: undefined }], head: null }).success).toBe(true);
  });
});
