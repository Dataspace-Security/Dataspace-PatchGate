/**
 * One-line site install (installers/site/web-install.md): enrolment-code gated bundle download (not consumed,
 * identical 403 for every failure, strict SHA256SUMS allow-list, Range/206 resume, audit on the bank chain),
 * the public site.sh, and CACHE_PACKAGE for the current Tactical agent builds after a connector enrols.
 */
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { TENANT_A, TENANT_B, configureTestEnv, resetDb } from "./helpers";
import { enrollBody, makeConnectorKey, sessionUserOf } from "./connector-helpers";

const repoDir = mkdtempSync(join(tmpdir(), "pg-site-repo-"));
const bundleDir = mkdtempSync(join(tmpdir(), "pg-site-bundles-"));
const V = "2026.10.1";
const BIG = Buffer.from(Array.from({ length: 5000 }, (_, i) => i % 251));
mkdirSync(join(bundleDir, V));
writeFileSync(join(bundleDir, V, `patchgate-site-${V}.tar.gz`), BIG);
writeFileSync(join(bundleDir, V, `patchgate-site-${V}-online.tar.gz`), "small online bundle");
writeFileSync(join(bundleDir, V, "install-site.sh"), '#!/usr/bin/env bash\nDEFAULT_SERVER="__PATCHGATE_URL__"\n');
writeFileSync(join(bundleDir, V, "not-listed.txt"), "should never be served");
writeFileSync(
  join(bundleDir, V, "SHA256SUMS"),
  [`${"1".repeat(64)}  patchgate-site-${V}.tar.gz`, `${"2".repeat(64)}  patchgate-site-${V}-online.tar.gz`, `${"3".repeat(64)}  install-site.sh`, ""].join("\n"),
);
writeFileSync(join(bundleDir, "LATEST"), `${V}\n`);

configureTestEnv({ REPO_DIR: repoDir, LOG_LEVEL: "error", TRUST_PROXY_HOPS: "1", PUBLIC_BASE_URL: "https://patchgate.test.local", PATCHGATE_SITE_BUNDLE_DIR: bundleDir });
const { prisma } = await import("@/lib/db");
const { createEnrollmentCode } = await import("@/lib/connector/admin");
const { redeemEnrollment, enrollCodeHash } = await import("@/lib/connector/enroll");
const { bundleFileResponse, siteScriptResponse } = await import("@/lib/connector/bundle-http");
const { cacheCurrentAgentBuilds } = await import("@/lib/deploy/connector-cache");
const { withTenant } = await import("@/lib/tenancy");

beforeEach(() => resetDb(prisma));
afterAll(async () => {
  await prisma.$disconnect();
  rmSync(repoDir, { recursive: true, force: true });
  rmSync(bundleDir, { recursive: true, force: true });
});

let ipSeq = 0;
const nextIp = () => `198.51.100.${++ipSeq}`;

async function newCode(tenantId = TENANT_A, name = "HQ") {
  const admin = sessionUserOf(await prisma.user.upsert({ where: { upn: "admin@pg" }, update: {}, create: { upn: "admin@pg", name: "A", role: "ADMIN" } }));
  return createEnrollmentCode(admin, { tenantId, name });
}

function get(version: string, file: string, code: string | null, extra: Record<string, string> = {}, ip = nextIp()) {
  const headers: Record<string, string> = { "x-forwarded-for": ip, ...extra };
  if (code !== null) headers.authorization = `PatchGate-Enrolment ${code}`;
  return bundleFileResponse(new Request(`https://patchgate.test.local/install/bundle/${version}/${file}`, { headers }), version, file);
}

describe("bundle download with an enrolment code", () => {
  it("serves SHA256SUMS + archives (full and Range/206) without consuming the code, and audits each file", async () => {
    const created = await newCode();
    expect(created.siteInstallCommand).toBe(`curl -fsSL https://patchgate.test.local/install/site.sh | sudo bash -s -- --code ${created.code} --fingerprint ${created.fingerprint}`);
    expect(created.bundleVersion).toBe(V);
    expect(created.usbInstallCommand).toContain(`--bundle patchgate-site-${V}.tar.gz --server https://patchgate.test.local --code ${created.code}`);

    const sums = await get("latest", "SHA256SUMS", created.code);
    expect(sums.status).toBe(200);
    expect(sums.headers.get("cache-control")).toBe("no-store");
    expect(await sums.text()).toContain(`patchgate-site-${V}.tar.gz`);

    const full = await get(V, `patchgate-site-${V}.tar.gz`, created.code);
    expect(full.status).toBe(200);
    expect(full.headers.get("content-length")).toBe(String(BIG.length));
    expect(full.headers.get("accept-ranges")).toBe("bytes");
    expect(full.headers.get("content-type")).toBe("application/gzip");
    expect(Buffer.from(await full.arrayBuffer()).equals(BIG)).toBe(true);

    const part = await get("latest", `patchgate-site-${V}.tar.gz`, created.code, { range: "bytes=4000-" });
    expect(part.status).toBe(206);
    expect(part.headers.get("content-range")).toBe(`bytes 4000-4999/${BIG.length}`);
    expect(part.headers.get("content-length")).toBe("1000");
    expect(Buffer.from(await part.arrayBuffer()).equals(BIG.subarray(4000))).toBe(true);

    const beyond = await get(V, `patchgate-site-${V}.tar.gz`, created.code, { range: `bytes=${BIG.length}-` });
    expect(beyond.status).toBe(416);
    expect(beyond.headers.get("content-range")).toBe(`bytes */${BIG.length}`);

    // unsigned bundle → 404 for the signature; the code is still unused
    expect((await get(V, "SHA256SUMS.sig", created.code)).status).toBe(404);
    const enrollment = await prisma.connectorEnrollment.findUniqueOrThrow({ where: { id: enrollCodeHash(created.code) } });
    expect(enrollment.usedAt).toBeNull();

    // full + ranged part (the 416 transferred nothing) — on the BANK's chain, never the code
    const audits = await prisma.auditEvent.findMany({ where: { action: "connector.bundle_downloaded" }, orderBy: { seq: "asc" } });
    expect(audits).toHaveLength(2);
    for (const a of audits) {
      expect(a.tenantId).toBe(TENANT_A);
      expect(JSON.stringify({ ...a, seq: String(a.seq) })).not.toContain(created.code);
      expect(a.payload).toMatchObject({ siteName: "HQ", version: V, file: `patchgate-site-${V}.tar.gz`, codeHashPrefix: enrollCodeHash(created.code).slice(0, 16) });
    }
    expect(audits[0].payload).toMatchObject({ sourceIp: expect.stringMatching(/^198\.51\.100\./), range: null });
    expect(audits[1].payload).toMatchObject({ range: "4000-4999" });
  });

  it("answers the SAME 403 for wrong, malformed, missing, used, expired and inactive-bank codes", async () => {
    const used = await newCode(TENANT_A, "Used site");
    await redeemEnrollment(enrollBody(used.code, makeConnectorKey()));
    const expired = await newCode(TENANT_A, "Expired site");
    await prisma.connectorEnrollment.update({ where: { id: enrollCodeHash(expired.code) }, data: { expiresAt: new Date(Date.now() - 1000) } });
    const otherBank = await newCode(TENANT_B, "Bank B site");
    await prisma.tenant.update({ where: { id: TENANT_B }, data: { active: false } });

    const responses = await Promise.all([
      get(V, "SHA256SUMS", "ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ"),
      get(V, "SHA256SUMS", "not-a-code"),
      get(V, "SHA256SUMS", null),
      get(V, "SHA256SUMS", used.code),
      get(V, "SHA256SUMS", expired.code),
      get(V, `patchgate-site-${V}.tar.gz`, otherBank.code),
      get("no-such-version", "SHA256SUMS", "ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ"),
    ]);
    const bodies = await Promise.all(responses.map((r) => r.text()));
    expect(responses.map((r) => r.status)).toEqual([403, 403, 403, 403, 403, 403, 403]);
    expect(new Set(bodies).size).toBe(1);
    expect(await prisma.auditEvent.count({ where: { action: "connector.bundle_downloaded" } })).toBe(0);
  });

  it("serves only names listed in SHA256SUMS: unlisted, traversal and unknown versions are 404", async () => {
    const { code } = await newCode();
    for (const [version, file] of [
      [V, "not-listed.txt"],
      [V, "..%2F..%2Fetc%2Fpasswd"],
      [V, "../LATEST"],
      ["..", "LATEST"],
      ["latest", "SHA256SUMS.online"],
      ["9.9.9", "SHA256SUMS"],
    ] as const) {
      const r = await get(version, file, code);
      expect([version, file, r.status]).toEqual([version, file, 404]);
    }
    expect(await prisma.auditEvent.count({ where: { action: "connector.bundle_downloaded" } })).toBe(0);
  });

  it("blocks an address after repeated wrong codes (429), other addresses unaffected", async () => {
    const ip = "203.0.113.7";
    for (let i = 0; i < 10; i++) expect((await get(V, "SHA256SUMS", "ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZY", {}, ip)).status).toBe(403);
    const { code } = await newCode();
    const blocked = await get(V, "SHA256SUMS", code, {}, ip);
    expect(blocked.status).toBe(429);
    expect(Number(blocked.headers.get("retry-after"))).toBeGreaterThan(0);
    expect((await get(V, "SHA256SUMS", code)).status).toBe(200);
  });
});

describe("public site.sh", () => {
  it("serves the latest install-site.sh with the PatchGate origin baked in (no auth, no-store)", async () => {
    const r = await siteScriptResponse();
    expect(r.status).toBe(200);
    expect(r.headers.get("content-type")).toMatch(/^text\/x-shellscript/);
    expect(r.headers.get("cache-control")).toBe("no-store");
    expect(r.headers.get("x-patchgate-bundle-version")).toBe(V);
    expect(await r.text()).toBe('#!/usr/bin/env bash\nDEFAULT_SERVER="https://patchgate.test.local"\n');
  });
});

describe("after enrolment: the current Tactical agent builds are queued for the site cache", () => {
  async function agentRelease(version: string, arch: string, verification: "VERIFIED" | "PENDING" = "VERIFIED") {
    const assetName = `tacticalagent-v${version}-windows-${arch}.exe`;
    return prisma.mirroredRelease.create({
      data: {
        component: "TACTICAL_AGENT",
        version,
        assetName,
        sourceUrl: "https://github.com/amidaware/rmmagent/releases",
        sha256: `${version}-${arch}`.padEnd(64, "0").replace(/[^a-f0-9]/g, "a").slice(0, 64),
        sizeBytes: BigInt(4321),
        repoPath: `tactical/agent/${version}/${assetName}`,
        verification,
      },
    });
  }

  it("queues CACHE_PACKAGE for the newest VERIFIED build of each arch — once (idempotent)", async () => {
    const amd = await agentRelease("2.12.0", "amd64");
    const x86 = await agentRelease("2.12.0", "386");
    await agentRelease("2.11.0", "amd64");
    await agentRelease("2.13.0", "amd64", "PENDING");

    const { code } = await newCode();
    const r = await redeemEnrollment(enrollBody(code, makeConnectorKey()));
    const jobs = await prisma.connectorJob.findMany({ where: { connectorId: r.connectorId, type: "CACHE_PACKAGE" } });
    const shas = jobs.map((j) => (j.payload as { package: { sha256: string; kind: string; size: number } }).package);
    expect(shas.map((p) => p.sha256).sort()).toEqual([amd.sha256, x86.sha256].sort());
    expect(shas.every((p) => p.kind === "agent" && p.size === 4321)).toBe(true);
    expect(jobs.every((j) => j.tenantId === TENANT_A && j.status === "QUEUED")).toBe(true);

    // again (e.g. a second producer, or the re-key of the same site): nothing new is queued
    await withTenant(TENANT_A, (tx) => cacheCurrentAgentBuilds(tx, { id: r.connectorId, tenantId: TENANT_A }));
    const { code: again } = await newCode(TENANT_A, "HQ");
    await redeemEnrollment(enrollBody(again, makeConnectorKey()));
    expect(await prisma.connectorJob.count({ where: { connectorId: r.connectorId, type: "CACHE_PACKAGE" } })).toBe(2);
  });

  it("enrols normally when no verified agent build exists (nothing queued)", async () => {
    const { code } = await newCode();
    const r = await redeemEnrollment(enrollBody(code, makeConnectorKey()));
    expect(await prisma.connectorJob.count({ where: { connectorId: r.connectorId } })).toBe(0);
  });
});
