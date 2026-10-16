/**
 * LIVE internet test of the third-party fetcher (opt-in: LIVE_FETCH=1).
 * Downloads the real PowerShell 7 MSI (~110 MB, Microsoft-signed, versioned GitHub release URL).
 * Chrome is NOT used for the success path: its winget URL is a rolling "latest" link, so the
 * manifest hash goes stale whenever Google ships — the fetcher (correctly) rejects that.
 */
import { mkdtempSync, rmSync, existsSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { configureTestEnv, resetDb } from "./helpers";

const repoDir = mkdtempSync(join(tmpdir(), "pg-repo-"));
configureTestEnv({ REPO_DIR: repoDir, QUARANTINE_HOURS: "48" });

const { prisma } = await import("@/lib/db");
const { fetchApp } = await import("@/lib/fetch/thirdparty");

beforeEach(() => resetDb(prisma));
afterAll(async () => {
  await prisma.$disconnect();
  rmSync(repoDir, { recursive: true, force: true });
});

describe.runIf(process.env.LIVE_FETCH === "1")("live fetch", () => {
  it("publishes PowerShell after hash + Microsoft signature verification, quarantined", { timeout: 600_000 }, async () => {
    const app = await prisma.app.create({
      data: {
        wingetId: "Microsoft.PowerShell",
        displayName: "PowerShell 7",
        inventoryMatch: "^PowerShell 7",
        expectedPublisher: "O=Microsoft Corporation",
        allowedDomains: ["github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"],
      },
    });
    const r = await fetchApp(app);
    expect(r.status, JSON.stringify(r)).toBe("published");

    const v = await prisma.appVersion.findFirstOrThrow({ where: { appId: app.id }, include: { patch: true } });
    expect(v.verification).toBe("VERIFIED");
    expect(v.availableAt!.getTime()).toBeGreaterThan(Date.now() + 47 * 3_600_000);
    expect(v.patch?.kind).toBe("THIRD_PARTY");
    const file = join(repoDir, ...v.repoPath!.split("/"));
    expect(existsSync(file)).toBe(true);
    expect(statSync(file).size).toBeGreaterThan(10_000_000);

    // Second run: nothing new
    expect((await fetchApp(app)).status).toBe("up-to-date");
  });

  it("rejects when the pinned publisher does not match", { timeout: 600_000 }, async () => {
    const app = await prisma.app.create({
      data: {
        wingetId: "Microsoft.PowerShell",
        displayName: "PowerShell 7",
        inventoryMatch: "^PowerShell 7",
        expectedPublisher: "O=Not Microsoft Inc",
        allowedDomains: ["github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"],
      },
    });
    const r = await fetchApp(app);
    expect(r.status).toBe("rejected");
    if (r.status === "rejected") expect(r.reason).toMatch(/publisher mismatch/);
    expect(await prisma.patch.count()).toBe(0);
  });

  it("rejects when the installer host is not on the app's allow-list", { timeout: 120_000 }, async () => {
    const app = await prisma.app.create({
      data: {
        wingetId: "Google.Chrome",
        displayName: "Google Chrome",
        inventoryMatch: "^Google Chrome$",
        expectedPublisher: "O=Google LLC",
        allowedDomains: ["downloads.example.com"],
      },
    });
    const r = await fetchApp(app);
    expect(r.status).toBe("rejected");
    if (r.status === "rejected") expect(r.reason).toMatch(/not allowed/);
  });
});

describe.runIf(process.env.LIVE_FETCH === "1")("live Tactical mirror", () => {
  it("mirrors rmmagent exes against GitHub digests and holds unsigned/undigested items for approval", { timeout: 600_000 }, async () => {
    const { mirrorTacticalReleases, decideMirror } = await import("@/lib/fetch/tactical");
    const out = await mirrorTacticalReleases();
    const recs = await prisma.mirroredRelease.findMany();
    expect(recs.length).toBeGreaterThanOrEqual(2);
    expect(recs.every((r) => r.verification !== "REJECTED"), JSON.stringify(out)).toBe(true);

    const server = recs.find((r) => r.component === "TACTICAL_SERVER");
    expect(server?.verification).toBe("PENDING");
    const servedBefore = existsSync(join(repoDir, ...server!.repoPath.split("/")));
    expect(servedBefore).toBe(false);

    await decideMirror(server!.id, true, "admin@test");
    expect(existsSync(join(repoDir, ...server!.repoPath.split("/")))).toBe(true);
    expect((await prisma.mirroredRelease.findUniqueOrThrow({ where: { id: server!.id } })).verification).toBe("VERIFIED");

    // idempotent
    const again = await mirrorTacticalReleases();
    expect(Object.values(again).every((s) => s === "up-to-date")).toBe(true);
  });
});

describe.runIf(process.env.LIVE_FETCH === "1")("live EXE fetch", () => {
  it("publishes Git for Windows (Inno EXE) with FIXED silent switches after signature check", { timeout: 600_000 }, async () => {
    const app = await prisma.app.create({
      data: {
        wingetId: "Git.Git",
        displayName: "Git for Windows",
        inventoryMatch: "^Git$",
        expectedPublisher: "O=Johannes Schindelin",
        allowedDomains: ["github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"],
      },
    });
    const r = await fetchApp(app);
    expect(r.status, JSON.stringify(r)).toBe("published");
    const v = await prisma.appVersion.findFirstOrThrow({ where: { appId: app.id } });
    expect(v).toMatchObject({
      installerKind: "EXE",
      installerType: "inno",
      silentArgs: "/SP- /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /ALLUSERS",
      verification: "VERIFIED",
    });
    expect(v.repoPath).toMatch(/^pkgs\/Git\.Git\/.+\.exe$/);
    expect(existsSync(join(repoDir, ...v.repoPath!.split("/")))).toBe(true);
  });
});
