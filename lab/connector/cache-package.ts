/**
 * LAB helper: ask a bank site's connector to cache packages NOW, through PatchGate's own service
 * (ensurePackageCached → a signed CACHE_PACKAGE job), instead of waiting for a change request to need them.
 * Production never needs this: deployments and WU scans enqueue CACHE_PACKAGE themselves.
 *
 *   cd patchgate-web && npx tsx ../lab/connector/cache-package.ts --bank bank-a Mozilla.Firefox PuTTY.PuTTY agent:2.10.0:amd64
 *   … --sync               also queue a SYNC_AGENTS job now (new Tactical agents otherwise appear with the
 *                          hourly sync), e.g. right after the Sandbox PC enrolled
 *   … --stage-agent 2.10.0   first registers the OLDER agent build staged by lab/fixtures/stage-old-agent.sh
 *                            (GitHub-digest-verified) as a VERIFIED mirror row, so the Sandbox PC can install
 *                            it from the site cache and PatchGate later has a real 2.10.0 → 2.11.0 upgrade.
 * Needs the env from lab/patchgate/env.sh (bash lab/connector/cache.sh wraps all of this).
 */
import { registerHooks, createRequire } from "node:module";
import { createHash } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { pathToFileURL } from "node:url";

// App modules import "server-only" (throws outside React Server Components); a CLI is server-side.
const appRequire = createRequire(join(process.cwd(), "package.json"));
const EMPTY = pathToFileURL(join(dirname(appRequire.resolve("server-only")), "empty.js")).href;
registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === "server-only") return { url: EMPTY, shortCircuit: true };
    return nextResolve(specifier, context);
  },
});

async function main(argv: string[]): Promise<number> {
  const { withPlatform, withTenant } = await import("@/lib/tenancy");
  const { ensurePackageCached } = await import("@/lib/deploy/connector-cache");
  const { PackageSizer } = await import("@/lib/deploy/connector-plan");
  const { appVersionToPackage, agentReleaseToPackage, versionPublisher } = await import("@/lib/thirdparty/package-from-db");
  const { env } = await import("@/lib/env");
  const { prisma } = await import("@/lib/db");
  const { enqueueJob } = await import("@/lib/connector/queue");

  let bank = "bank-a";
  let stageAgent: string | null = null;
  let sync = false;
  const selectors: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--bank") bank = argv[++i];
    else if (argv[i] === "--stage-agent") stageAgent = argv[++i];
    else if (argv[i] === "--sync") sync = true;
    else selectors.push(argv[i]);
  }

  try {
    if (stageAgent) {
      for (const arch of ["amd64", "386"]) {
        const assetName = `tacticalagent-v${stageAgent}-windows-${arch}.exe`;
        const repoPath = `tactical/agent/${stageAgent}/${assetName}`;
        const file = join(env().REPO_DIR, repoPath);
        const sha256 = createHash("sha256").update(readFileSync(file)).digest("hex");
        await withPlatform((tx) =>
          tx.mirroredRelease.upsert({
            where: { component_version_assetName: { component: "TACTICAL_AGENT", version: stageAgent!, assetName } },
            create: {
              component: "TACTICAL_AGENT",
              version: stageAgent!,
              assetName,
              repoPath,
              sha256,
              sizeBytes: BigInt(statSync(file).size),
              sourceUrl: `https://github.com/amidaware/rmmagent/releases/download/v${stageAgent}/${assetName}`,
              verification: "VERIFIED", // lab fixture: digest-matched against GitHub by stage-old-agent.sh
            },
            update: {},
          }),
        );
        console.log(`agent ${stageAgent} ${arch} registered (sha256 ${sha256.slice(0, 16)}…)`);
      }
    }

    const connector = await withPlatform((tx) =>
      tx.connector.findFirst({ where: { status: "ACTIVE", tenant: { slug: bank } }, orderBy: { enrolledAt: "asc" }, select: { id: true, tenantId: true, name: true } }),
    );
    if (!connector) throw new Error(`bank ${bank} has no active connector`);

    if (sync) {
      const now = new Date();
      const job = await withTenant(connector.tenantId, (tx) =>
        enqueueJob(tx, { tenantId: connector.tenantId, connectorId: connector.id, type: "SYNC_AGENTS", payload: {}, expiresAt: new Date(now.getTime() + 60 * 60_000) }, now),
      );
      console.log(`SYNC_AGENTS queued for ${connector.name}: ${job.id}`);
    }

    const sizer = new PackageSizer();
    for (const sel of selectors) {
      let pkg;
      if (sel.startsWith("agent:")) {
        const [, version, arch = "amd64"] = sel.split(":");
        const rel = await withPlatform((tx) =>
          tx.mirroredRelease.findFirst({ where: { component: "TACTICAL_AGENT", verification: "VERIFIED", version, assetName: { endsWith: `-windows-${arch}.exe` } } }),
        );
        if (!rel) throw new Error(`no VERIFIED agent ${version} ${arch}`);
        pkg = await sizer.toJobPackage(agentReleaseToPackage(rel));
      } else {
        const v = await withPlatform((tx) =>
          tx.appVersion.findFirst({ where: { app: { wingetId: sel }, verification: "VERIFIED", repoPath: { not: null } }, orderBy: { createdAt: "desc" }, include: { app: true } }),
        );
        if (!v) throw new Error(`no VERIFIED version of ${sel}`);
        pkg = await sizer.toJobPackage(
          appVersionToPackage({ ...v, wingetId: v.app.wingetId, publisher: versionPublisher(v, v.app.expectedPublisher) } as never),
        );
      }
      const state = await withTenant(connector.tenantId, (tx) => ensurePackageCached(tx, connector, pkg, new Date()));
      console.log(`${sel}: ${pkg.repoPath} (${pkg.size} bytes, sha256 ${pkg.sha256}) → ${JSON.stringify(state)}`);
    }
    return 0;
  } finally {
    await prisma.$disconnect();
  }
}

main(process.argv.slice(2)).then(
  (code) => (process.exitCode = code),
  (err: unknown) => {
    console.error(`cache-package failed: ${err instanceof Error ? err.message : String(err)}`);
    process.exitCode = 1;
  },
);
