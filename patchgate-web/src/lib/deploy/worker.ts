import "server-only";
import { Prisma } from "@prisma/client";
import { env } from "@/lib/env";
import { withPlatform, withTenant, type Tx } from "@/lib/tenancy";
import { DIRECT_TACTICAL_NOT_CONFIGURED, directTacticalConfig, legacyTacticalTenantId } from "@/lib/tactical/from-env";
import { appendAudit } from "@/lib/audit/service";
import { TacticalError, type TacticalClient } from "@/lib/tactical/client";
import { windowsInstallComplete } from "@/lib/tactical/deploy-plan";
import { compareVersions, isInstalledAtLeast } from "@/lib/thirdparty/version";
import type { PackageInput } from "@/lib/thirdparty/package-input";
import { agentReleaseToPackage, appVersionToPackage, pickAgentRelease, versionPublisher } from "@/lib/thirdparty/package-from-db";
import { verifiedAgentReleases } from "@/lib/approvals/load-eligible";
import { pushToEndpoint } from "./push";
import { isWithinWindow } from "./window";
import { exportAuditToSiem, siemSenderFromEnv } from "@/lib/audit/export";
import type { SyslogSender } from "@/lib/siem/syslog";
import { log } from "@/lib/log";
import { enqueueNotification } from "@/lib/notify/enqueue";
import { tenantUsesConnector } from "@/lib/connector/routing";
import { expireJobs, purgeFinishedJobs } from "@/lib/connector/queue";
import { purgeExpiredNonces } from "@/lib/connector/auth";
import { processPendingResults } from "@/lib/connector/results";
import { onJobsExpired, produceConnectorDeployments } from "./connector-deploy";
import { confirmConnectorDeployments } from "./connector-confirm";
import { enforceDeployDeadlines } from "./deadline";
import { verifyAuditChainsIncremental } from "@/lib/audit/verify-incremental";
import { rebuildConnectorDiscovery, scheduleConnectorInventory } from "@/lib/scan/connector-schedule";

const BATCH = 25;
const MAX_ATTEMPTS = 6;
const RETRY_MS = 10 * 60_000;
const BUSY_RETRY_MS = 5 * 60_000;
const OUTSIDE_WINDOW_RETRY_MS = 15 * 60_000;
const CONFIRM_TIMEOUT_MS = 6 * 60 * 60_000;
// A SENDING claim older than this means the worker died mid-push; the push is idempotent, so requeue.
const STALE_CLAIM_MS = 30 * 60_000;

const crInclude = {
  window: true,
  patches: { include: { patch: { include: { appVersion: { include: { app: true } } } } } },
} as const;

type CrWithPatches = Prisma.ChangeRequestGetPayload<{ include: typeof crInclude }>;

/** Network failures and 5xx are worth retrying; 4xx and safety-check failures are not. */
function isTransient(err: unknown): boolean {
  return err instanceof TacticalError && (err.status === undefined || err.status >= 500);
}

function errMsg(err: unknown): string {
  return (err instanceof Error ? err.message : "unknown error").slice(0, 500);
}

function windowsGuidsOf(cr: CrWithPatches): Set<string> {
  return new Set(cr.patches.filter((p) => p.patch.kind === "WINDOWS").map((p) => p.patch.externalId));
}

type AgentReleases = Awaited<ReturnType<typeof verifiedAgentReleases>>;

interface PlannedPackage {
  pkg: PackageInput;
  /** How reconcile confirms success: installed-software inventory, or the agent's reported version */
  confirm: { by: "inventory"; match: string; version: string } | { by: "agent"; version: string };
}

function agentVersionsOf(cr: CrWithPatches): string[] {
  return cr.patches.flatMap(({ patch }) => (patch.kind === "AGENT_UPGRADE" && patch.agentVersion ? [patch.agentVersion] : []));
}

/** Packages for ONE endpoint: third-party apps + the agent build matching its architecture. */
function packagesFor(cr: CrWithPatches, releases: AgentReleases, goarch: string | null): PlannedPackage[] {
  return cr.patches.flatMap(({ patch }): PlannedPackage[] => {
    if (patch.kind === "THIRD_PARTY") {
      const v = patch.appVersion;
      if (!v || !v.repoPath) return [];
      const pkg = appVersionToPackage({ ...v, wingetId: v.app.wingetId, publisher: versionPublisher(v, v.app.expectedPublisher) });
      return [{ pkg, confirm: { by: "inventory", match: v.app.inventoryMatch, version: v.version } }];
    }
    if (patch.kind === "AGENT_UPGRADE" && patch.agentVersion) {
      const rel = pickAgentRelease(releases.get(patch.agentVersion) ?? [], goarch);
      if (!rel) throw new Error(`no approved agent ${patch.agentVersion} build for arch ${goarch ?? "unknown"}`);
      return [{ pkg: agentReleaseToPackage(rel), confirm: { by: "agent", version: patch.agentVersion } }];
    }
    return [];
  });
}

async function packagesConfirmed(tactical: TacticalClient, agentId: string, planned: readonly PlannedPackage[]): Promise<boolean> {
  const inv = planned.filter((p) => p.confirm.by === "inventory");
  const agent = planned.filter((p) => p.confirm.by === "agent");
  const inventory = inv.length > 0 ? await tactical.getSoftware(agentId) : [];
  const appsOk = inv.every((p) => p.confirm.by === "inventory" && isInstalledAtLeast(inventory, p.confirm.match, p.confirm.version));
  if (!appsOk) return false;
  if (agent.length === 0) return true;
  const current = await tactical.getAgent(agentId);
  return agent.every((p) => compareVersions(current.version, p.confirm.version) >= 0);
}

async function finishDeployment(
  tenantId: string,
  id: string,
  from: "SENDING" | "SENT",
  status: "SUCCEEDED" | "FAILED" | "TIMED_OUT",
  error: string | null,
): Promise<void> {
  await withTenant(tenantId, async (tx) => {
    const { count } = await tx.deployment.updateMany({
      where: { id, tenantId, status: from },
      data: { status, error, finishedAt: new Date() },
    });
    if (count === 1) {
      await appendAudit(
        { tenantId, actor: "system", action: `deployment.${status.toLowerCase()}`, entity: "Deployment", entityId: id, payload: { error } },
        tx,
      );
    }
  });
}

/**
 * 1. Push QUEUED deployments whose change request is inside its maintenance window.
 * Direct Tactical path: serves ONE bank only (LEGACY_TACTICAL_TENANT_ID) and only while that bank has no
 * ACTIVE site connector (then connector-deploy.ts takes over); every DB step is scoped to it.
 */
export async function processQueue(tactical: TacticalClient, now = new Date(), tenantId = legacyTacticalTenantId()): Promise<number> {
  if (await tenantUsesConnector(tenantId)) return 0;
  const direct = directTacticalConfig();
  if (!direct) return 0; // hosted mode: no direct Tactical link
  const PATCH_REPO_URL = direct.repoUrl;
  const { TACTICAL_INSTALL_SCRIPT_ID } = env();
  const db = <T>(fn: (tx: Tx) => Promise<T>): Promise<T> => withTenant(tenantId, fn);

  // Recover claims abandoned by a crashed/restarted worker (they would block the endpoint forever).
  const due = await db(async (tx) => {
    await tx.deployment.updateMany({
      where: { tenantId, status: "SENDING", OR: [{ claimedAt: null }, { claimedAt: { lt: new Date(now.getTime() - STALE_CLAIM_MS) } }] },
      data: { status: "QUEUED", note: "recovered after worker interruption", nextAttemptAt: now },
    });
    return tx.deployment.findMany({
      where: { tenantId, status: "QUEUED", nextAttemptAt: { lte: now }, changeRequest: { status: "DEPLOYING" } },
      orderBy: { nextAttemptAt: "asc" },
      take: BATCH,
      include: { endpoint: true, changeRequest: { include: crInclude } },
    });
  });
  const releases = await verifiedAgentReleases([...new Set(due.flatMap((d) => agentVersionsOf(d.changeRequest)))]);

  let processed = 0;
  for (const d of due) {
    const cr = d.changeRequest;
    if (cr.window && !isWithinWindow(cr.window, now)) {
      await db((tx) =>
        tx.deployment.updateMany({
          where: { id: d.id, status: "QUEUED" },
          data: { nextAttemptAt: new Date(now.getTime() + OUTSIDE_WINDOW_RETRY_MS) },
        }),
      );
      continue;
    }

    // Claim. The partial unique index allows only one SENDING/SENT deployment per endpoint.
    try {
      const { count } = await db((tx) =>
        tx.deployment.updateMany({
          where: { id: d.id, status: "QUEUED" },
          data: { status: "SENDING", attempts: { increment: 1 }, claimedAt: now },
        }),
      );
      if (count !== 1) continue; // another worker took it
    } catch (err: unknown) {
      if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === "P2002") {
        await db((tx) =>
          tx.deployment.update({
            where: { id: d.id },
            data: { nextAttemptAt: new Date(now.getTime() + BUSY_RETRY_MS), note: "endpoint busy with another change request" },
          }),
        );
        continue;
      }
      throw err;
    }

    const attempt = d.attempts + 1;
    try {
      // Agent upgrades need the PC architecture; fetch it from Tactical if we never stored it.
      let goarch = d.endpoint.goarch;
      if (!goarch && agentVersionsOf(cr).length > 0) {
        const a = await tactical.getAgent(d.endpoint.tacticalAgentId);
        goarch = a.goarch ?? null;
        await db((tx) => tx.endpoint.update({ where: { id: d.endpoint.id }, data: { goarch, agentVersion: a.version } }));
      }
      const outcome = await pushToEndpoint(tactical, {
        agentId: d.endpoint.tacticalAgentId,
        attempt,
        windowsGuids: windowsGuidsOf(cr),
        packages: packagesFor(cr, releases, goarch).map((p) => p.pkg),
        repoUrl: PATCH_REPO_URL,
        installScriptId: TACTICAL_INSTALL_SCRIPT_ID,
      });

      if (outcome.kind === "retry") {
        if (attempt >= MAX_ATTEMPTS) {
          await finishDeployment(tenantId, d.id, "SENDING", "FAILED", `gave up after ${attempt} attempts: ${outcome.reason}`);
        } else {
          await db((tx) =>
            tx.deployment.updateMany({
              where: { id: d.id, status: "SENDING" },
              data: { status: "QUEUED", note: outcome.reason, nextAttemptAt: new Date(now.getTime() + RETRY_MS) },
            }),
          );
        }
      } else {
        await db((tx) =>
          tx.deployment.updateMany({
            where: { id: d.id, status: "SENDING" },
            data: { status: "SENT", startedAt: now, targetGuids: outcome.targetGuids, note: outcome.note },
          }),
        );
      }
      processed++;
    } catch (err: unknown) {
      try {
        if (isTransient(err) && attempt < MAX_ATTEMPTS) {
          // Back off linearly: 10, 20, 30 ... minutes.
          await db((tx) =>
            tx.deployment.updateMany({
              where: { id: d.id, status: "SENDING" },
              data: { status: "QUEUED", note: `retrying: ${errMsg(err)}`, nextAttemptAt: new Date(now.getTime() + RETRY_MS * attempt) },
            }),
          );
          continue;
        }
        await finishDeployment(tenantId, d.id, "SENDING", "FAILED", errMsg(err));
      } catch (inner: unknown) {
        log.error("worker.deploy.record_failure_failed", { deploymentId: d.id, err: inner });
      }
    }
  }
  return processed;
}

/** 2. Confirm SENT deployments by reading back agent state (Tactical install is fire-and-forget). Legacy bank only. */
export async function reconcileSent(tactical: TacticalClient, now = new Date(), tenantId = legacyTacticalTenantId()): Promise<void> {
  if (await tenantUsesConnector(tenantId)) return; // confirmed from COLLECT results (connector-confirm.ts)
  const sent = await withTenant(tenantId, (tx) =>
    tx.deployment.findMany({
      where: { tenantId, status: "SENT" },
      include: { endpoint: true, changeRequest: { include: crInclude } },
    }),
  );
  const sentReleases = await verifiedAgentReleases([...new Set(sent.flatMap((d) => agentVersionsOf(d.changeRequest)))]);

  for (const d of sent) {
    const agentId = d.endpoint.tacticalAgentId;
    let done = false;
    try {
      const winDone =
        d.targetGuids.length === 0 ||
        windowsInstallComplete(await tactical.getUpdates(agentId), d.targetGuids);
      const planned = packagesFor(d.changeRequest, sentReleases, d.endpoint.goarch);
      done = winDone && (await packagesConfirmed(tactical, agentId, planned));
    } catch (err: unknown) {
      log.warn("worker.reconcile.agent_unreachable", { agentId, err: errMsg(err) });
    }

    // Timeout is evaluated even when the agent is unreachable.
    const expired = d.startedAt !== null && now.getTime() - d.startedAt.getTime() > CONFIRM_TIMEOUT_MS;
    if (done) await finishDeployment(tenantId, d.id, "SENT", "SUCCEEDED", null);
    else if (expired) await finishDeployment(tenantId, d.id, "SENT", "TIMED_OUT", "install not confirmed within timeout");
  }
}

/**
 * 3. Close change requests once every deployment is terminal — for every bank (no Tactical involved).
 * Each closure is written in that bank's scope and to that bank's audit chain.
 */
export async function finaliseChangeRequests(): Promise<void> {
  // One grouped count per status instead of loading every deployment row (50k PCs per request).
  const { deploying, counts } = await withPlatform(async (tx) => {
    const crs = await tx.changeRequest.findMany({ where: { status: "DEPLOYING" }, select: { id: true, tenantId: true } });
    const grouped =
      crs.length > 0
        ? await tx.deployment.groupBy({ by: ["changeRequestId", "status"], where: { changeRequestId: { in: crs.map((c) => c.id) } }, _count: { _all: true } })
        : [];
    return { deploying: crs, counts: grouped };
  });

  for (const cr of deploying) {
    const mine = counts.filter((c) => c.changeRequestId === cr.id);
    const total = mine.reduce((n, c) => n + c._count._all, 0);
    if (total === 0 || mine.some((c) => (c.status === "QUEUED" || c.status === "SENDING" || c.status === "SENT") && c._count._all > 0)) continue;
    const ok = mine.filter((c) => c.status === "SUCCEEDED").reduce((n, c) => n + c._count._all, 0);
    const status = ok === total ? "COMPLETED" : ok === 0 ? "FAILED" : "PARTIAL";

    await withTenant(cr.tenantId, async (tx) => {
      const { count } = await tx.changeRequest.updateMany({
        where: { id: cr.id, tenantId: cr.tenantId, status: "DEPLOYING" },
        data: { status, completedAt: new Date() },
      });
      if (count === 1) {
        await appendAudit(
          {
            tenantId: cr.tenantId,
            actor: "system",
            action: "change_request.finalise",
            entity: "ChangeRequest",
            entityId: cr.id,
            payload: { status, succeeded: ok, total },
          },
          tx,
        );
        if (status !== "COMPLETED") await enqueueNotification(tx, { event: "CR_FAILED", tenantId: cr.tenantId, crId: cr.id, status, succeeded: ok, total });
      }
    });
  }
}

export interface TickDeps {
  /** Direct Tactical link of the legacy bank; null in hosted mode (legacy steps are skipped). */
  tactical: TacticalClient | null;
  siem?: SyslogSender | null;
  /** Optional extra steps (scan ingestion, fetcher) injected by the route */
  extraSteps?: ReadonlyArray<{ name: string; run: () => Promise<unknown> }>;
  /** Observer called after every step with its outcome and duration (monitoring: WorkerStepRun). */
  onStep?: (name: string, status: StepStatus, durationMs: number) => void;
}

/** "ok" / a short summary, or "FAILED: <reason>" */
export type StepStatus = string;

export interface TickResult {
  /** false when any step failed (the HTTP status stays 200 — monitoring reads this + /api/ready) */
  ok: boolean;
  pushed: number;
  siem: { before: StepStatus; after: StepStatus };
  steps: Record<string, StepStatus>;
}

const FAILED = "FAILED: ";

/**
 * One tick = independent steps. A failing step (SIEM down, CA file missing, Tactical unreachable, DB
 * hiccup in one bank) is logged and reported, and every other step still runs.
 */
export async function runWorkerTick(deps: TickDeps): Promise<TickResult> {
  const now = new Date();
  const steps: Record<string, StepStatus> = {};
  const step = async (name: string, fn: () => Promise<StepStatus | void>): Promise<void> => {
    const started = Date.now();
    try {
      steps[name] = (await fn()) || "ok";
    } catch (err: unknown) {
      steps[name] = `${FAILED}${errMsg(err)}`;
      log.error("worker.tick.step_failed", { step: name, durationMs: Date.now() - started, err });
    }
    deps.onStep?.(name, steps[name], Date.now() - started);
  };

  let sender: SyslogSender | null = null;
  await step("siemSetup", async () => {
    sender = deps.siem === undefined ? siemSenderFromEnv() : deps.siem;
    return sender ? "ok" : "not configured";
  });

  // Export FIRST so audit shipping never waits behind slow Tactical calls, and again at the end.
  await step("siemBefore", () => exportStep(sender, now));

  // ---- Connector-backed banks (signed job pipeline). Later steps take a fresh clock: results applied
  //      earlier in this tick may have stamped times after `now`. ----
  await step("connectorSweep", async () => {
    const expired = await expireJobs(now);
    await onJobsExpired(expired, now);
    const nonces = await purgeExpiredNonces(now);
    return `expired ${expired.length}, nonces purged ${nonces}`;
  });
  await step("connectorResults", async () => {
    const r = await processPendingResults();
    return `applied ${r.applied}${r.failed ? `, failed ${r.failed}` : ""}${r.deferred ? ", rest deferred" : ""}`;
  });
  await step("connectorDeploy", async () => {
    const r = await produceConnectorDeployments(new Date());
    return `enqueued ${r.enqueued}${r.stopped ? `, ring-stopped ${r.stopped}` : ""}`;
  });
  await step("connectorConfirm", async () => {
    const r = await confirmConnectorDeployments(new Date());
    return `collect ${r.collectJobs}, succeeded ${r.succeeded}, timed out ${r.timedOut}`;
  });
  await step("connectorSchedule", async () => {
    const r = await scheduleConnectorInventory(new Date());
    return `sync ${r.sync}, scan ${r.scan}, collect ${r.collect}, wu ${r.wuScan}, tactical-audit ${r.tacticalAudit}, approval-check ${r.approvalCheck}`;
  });
  await step("connectorDiscovery", async () => `rebuilt ${await rebuildConnectorDiscovery()}`);

  // ---- Direct Tactical link (legacy bank without a connector) ----
  let pushed = 0;
  const tactical = deps.tactical;
  await step("deployQueue", async () => {
    if (!tactical) return DIRECT_TACTICAL_NOT_CONFIGURED;
    pushed = await processQueue(tactical, now);
    return `pushed ${pushed}`;
  });
  await step("reconcile", async () => (tactical ? reconcileSent(tactical, now) : DIRECT_TACTICAL_NOT_CONFIGURED));
  await step("deadline", async () => {
    const r = await enforceDeployDeadlines(new Date());
    return r.timedOut > 0 ? `timed out ${r.timedOut} in ${r.changeRequests} change request(s)` : "ok";
  });
  await step("finalise", () => finaliseChangeRequests());
  await step("connectorPurge", async () => `purged ${await purgeFinishedJobs(new Date())}`);
  await step("auditVerify", async () => {
    const r = await verifyAuditChainsIncremental();
    // A broken chain is an integrity alarm (log.error + /api/ready auditChain=false), not a failed step.
    return r.valid ? `ok (${r.chains} chains, ${r.verified} new events)` : `BROKEN: ${r.brokenChains} audit chain(s) failed verification`;
  });
  for (const extra of deps.extraSteps ?? []) {
    await step(extra.name, async () => {
      const r = await extra.run();
      return typeof r === "string" ? r : undefined; // a step may report a status (e.g. "skipped: …")
    });
  }
  await step("siemAfter", () => exportStep(sender, new Date()));

  const ok = Object.values(steps).every((s) => !s.startsWith(FAILED));
  if (!ok) log.warn("worker.tick.partial", { failed: Object.keys(steps).filter((k) => steps[k].startsWith(FAILED)) });
  return { ok, pushed, siem: { before: steps.siemBefore, after: steps.siemAfter }, steps };
}

/** SIEM export of every audit chain; throws on failure (the step wrapper records it). */
async function exportStep(sender: SyslogSender | null, now: Date): Promise<StepStatus> {
  if (!sender) return "not configured";
  const r = await exportAuditToSiem(sender, now);
  return `exported ${r.exported}${r.heartbeat ? " + heartbeat" : ""}`;
}
