/**
 * LIVE Windows-update validation (opt-in: WU_LIVE=1, Windows host, internet). READ-ONLY on this host:
 *   1. download the real wsusscn2.cab (~700 MB) through the pipeline and verify the Microsoft signature
 *   2. (WU_LIVE_SCAN=1) run scripts/endpoint/Invoke-PatchGateWuScan.ps1 against it (scan only, never installs)
 *      and validate the output against resultSchemas.WU_SCAN
 *   3. (WU_LIVE_DOWNLOAD=1) bind WU_LIVE_UPDATE_ID from the Microsoft Update Catalog, fetch + verify one of its files
 * Separately (WU_LIVE=1, any OS): ONE live Microsoft Update Catalog lookup — the authoritative update → files
 * binding (finding #2) parsed from the real service.
 * WU_LIVE_REPO_DIR keeps the repo between runs (the cab is reused instead of downloaded again).
 */
import { execFile } from "node:child_process";
import { existsSync, mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";
import { afterAll, describe, expect, it } from "vitest";
import { configureTestEnv } from "./helpers";

const run = promisify(execFile);
const keepRepo = !!process.env.WU_LIVE_REPO_DIR;
const repoDir = process.env.WU_LIVE_REPO_DIR ?? mkdtempSync(join(tmpdir(), "pg-wu-live-"));
configureTestEnv({ REPO_DIR: repoDir, QUARANTINE_HOURS: "0" });

const { prisma } = await import("@/lib/db");
const { fetchScanCab, latestScanCabPackage } = await import("@/lib/winupdate/cab");
const { resultSchemas } = await import("@/lib/connector/protocol");
const { processFile } = await import("@/lib/winupdate/files");
const { lookupCatalogUpdate, planCatalogBinding } = await import("@/lib/winupdate/catalog");
const { resolveUpdate } = await import("@/lib/winupdate/resolve");

// 2024-10 Cumulative Update for Server 2025 x64 (KB5044284): checkpoint + LCU, both with SHA-1 + SHA-256.
const LIVE_CATALOG_ID = process.env.WU_LIVE_CATALOG_ID ?? "a62b9737-1fe8-4df1-94b4-8ec61855a8d0";

afterAll(async () => {
  await prisma.$disconnect();
  if (!keepRepo) rmSync(repoDir, { recursive: true, force: true });
});

describe.runIf(process.env.WU_LIVE === "1" && process.platform === "win32")("live Windows update pipeline", () => {
  it("downloads + verifies the real wsusscn2.cab", { timeout: 3_600_000 }, async () => {
    const r = await fetchScanCab();
    expect(["published", "up-to-date"], JSON.stringify(r)).toContain(r.status);
    const pkg = await prisma.$transaction((tx) => latestScanCabPackage(tx));
    expect(pkg?.kind).toBe("wsusscan");
    const file = join(repoDir, ...pkg!.repoPath.split("/"));
    expect(statSync(file).size).toBe(pkg!.size);
    const cab = await prisma.wsusScanCab.findUniqueOrThrow({ where: { sha256: pkg!.sha256 } });
    expect(cab.signerSubject).toMatch(/O=Microsoft Corporation/);
    expect((await fetchScanCab()).status).toBe("up-to-date");
  });

  it.runIf(process.env.WU_LIVE_SCAN === "1")("scans this host offline (read-only) and validates WU_SCAN output", { timeout: 3_600_000 }, async () => {
    const pkg = await prisma.$transaction((tx) => latestScanCabPackage(tx));
    const file = join(repoDir, ...pkg!.repoPath.split("/"));
    expect(existsSync(file)).toBe(true);
    const script = resolve("scripts/endpoint/Invoke-PatchGateWuScan.ps1");
    const { stdout } = await run("powershell.exe", ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script], {
      env: { ...process.env, PG_CAB_FILE: file, PG_SHA256: pkg!.sha256, PG_SCAN_TIMEOUT_SEC: "3000" },
      timeout: 3_300_000,
      maxBuffer: 64 * 1024 * 1024,
      windowsHide: true,
    });
    const line = stdout.split(/\r?\n/).find((l) => l.startsWith("PATCHGATE_RESULT="));
    expect(line, stdout.slice(-2000)).toBeTruthy();
    const body = JSON.parse(line!.slice("PATCHGATE_RESULT=".length)) as { ok: boolean; updates?: unknown[]; error?: string };
    expect(body.ok, body.error).toBe(true);
    const parsed = resultSchemas.WU_SCAN.parse({ agents: [{ agentId: "local-host-01", updates: body.updates }] });
    const updates = parsed.agents[0].updates ?? [];
    const files = updates.flatMap((u) => u.files);
    console.info(JSON.stringify({ updates: updates.length, files: files.length, sample: updates.slice(0, 3) }, null, 1).slice(0, 4000));
  });

  it.runIf(process.env.WU_LIVE_DOWNLOAD === "1")("binds a real update from the catalog, fetches + verifies one of its files", { timeout: 3_600_000 }, async () => {
    const updateId = process.env.WU_LIVE_UPDATE_ID ?? LIVE_CATALOG_ID;
    await prisma.winUpdateFile.deleteMany({ where: { updateId } });
    await prisma.$executeRawUnsafe(`DELETE FROM "WinUpdate" WHERE "id" = '${updateId.replace(/[^0-9a-f-]/gi, "")}'`);
    const u = await prisma.winUpdate.create({ data: { id: updateId, revision: 0, title: "live validation" } });
    expect(await resolveUpdate(u)).toBe("resolved");
    const files = await prisma.winUpdateFile.findMany({ where: { updateId, source: "CATALOG" } });
    expect(files.length).toBeGreaterThan(0);
    expect(await processFile(files[files.length - 1])).toBe("verified");
    const v = await prisma.winUpdateFile.findUniqueOrThrow({ where: { id: files[files.length - 1].id } });
    console.info(JSON.stringify({ url: v.url, sha1: v.sha1, sha256: v.sha256, size: Number(v.sizeBytes), signer: v.signerSubject?.split(/\r?\n/).join(", ") }));
    expect(v.signerSubject).toMatch(/O=Microsoft Corporation/);
    expect(statSync(join(repoDir, ...v.repoPath!.split("/"))).size).toBe(Number(v.sizeBytes));
  });
});

describe.runIf(process.env.WU_LIVE === "1")("live Microsoft Update Catalog (authoritative update → files)", () => {
  it("looks up ONE real update: official URLs, SHA-1 + SHA-256, KB/title/severity", { timeout: 120_000 }, async () => {
    const r = await lookupCatalogUpdate(LIVE_CATALOG_ID);
    expect(r.found).toBe(true);
    if (!r.found) return;
    const b = planCatalogBinding(r);
    console.info(JSON.stringify(b, null, 1).slice(0, 3000));
    expect(b.ok, JSON.stringify(b)).toBe(true);
    if (!b.ok) return;
    if (!process.env.WU_LIVE_CATALOG_ID) {
      expect(b).toMatchObject({ kb: "KB5044284", msrcSeverity: "Critical", classification: "Security Updates" });
      expect(b.files.map((f) => f.name)).toEqual([expect.stringContaining("kb5043080"), expect.stringContaining("kb5044284")]);
    }
    expect(b.files.every((f) => /^[0-9a-f]{40}$/.test(f.sha1) && /^[0-9a-f]{64}$/.test(f.expectedSha256 ?? ""))).toBe(true);
    // an unknown GUID is not found (no binding can be invented)
    expect(await lookupCatalogUpdate("00000000-1111-2222-3333-444444444444")).toEqual({ found: false });
  });
});
