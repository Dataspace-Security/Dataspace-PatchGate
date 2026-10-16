import "server-only";
import { withPlatform, withTenant, type Tx } from "@/lib/tenancy";
import { log } from "@/lib/log";
import { compareVersions, isInstalledAtLeast } from "@/lib/thirdparty/version";
import { normGuid } from "@/lib/tactical/deploy-plan";
import { isOnline } from "@/lib/connector/policy";
import { MAX_AGENTS_PER_JOB } from "@/lib/connector/protocol";
import { enqueueCollect } from "@/lib/scan/connector-schedule";
import { crPlanInclude, type CrForPlan } from "./connector-plan";
import { AuditBuffer, finish } from "./connector-state";

/**
 * Confirmation of connector deployments, same semantics as the direct path (worker.ts reconcileSent):
 * the install was STARTED; it counts as SUCCEEDED only when collected inventory taken after the start
 * shows it — Windows GUIDs installed, managed app at ≥ the target version, agent at ≥ the target.
 * Not confirmed within CONFIRM_TIMEOUT_MS → TIMED_OUT. Fresh inventory is requested with COLLECT jobs
 * (batched per connector), so confirmation never needs a direct Tactical call.
 */

export const CONFIRM_TIMEOUT_MS = 6 * 60 * 60_000;
/** Windows installs take a while: ask for inventory this long after the start. Packages: right away. */
const WINDOWS_SETTLE_MS = 10 * 60_000;
/** Re-ask for inventory every so often while a deployment stays unconfirmed. */
const RECOLLECT_EVERY_MS = 30 * 60_000;

/** SENT deployments are confirmed in chunks, each in its own short transaction. */
const CONFIRM_CHUNK = 200;

type SentRow = Awaited<ReturnType<typeof loadSentChunk>>[number];

async function loadSentChunk(tx: Tx, tenantId: string, after: string | null, endpointIds?: readonly string[]) {
  return tx.deployment.findMany({
    where: {
      tenantId,
      status: "SENT",
      connectorId: { not: null },
      ...(endpointIds ? { endpointId: { in: [...endpointIds] } } : {}),
      ...(after ? { id: { gt: after } } : {}),
    },
    orderBy: { id: "asc" },
    take: CONFIRM_CHUNK,
    include: { endpoint: true, changeRequest: { include: crPlanInclude } },
  });
}

async function windowsConfirmed(tx: Tx, tenantId: string, endpointId: string, guids: readonly string[]): Promise<boolean> {
  if (guids.length === 0) return true;
  const wanted = [...new Set(guids.map(normGuid))];
  const installed = await tx.endpointPatchState.count({
    where: { tenantId, endpointId, status: "INSTALLED", patch: { kind: "WINDOWS", externalId: { in: wanted } } },
  });
  return installed >= wanted.length;
}

async function packagesConfirmed(tx: Tx, tenantId: string, d: SentRow, cr: CrForPlan): Promise<boolean> {
  const apps = cr.patches.filter((p) => p.patch.kind === "THIRD_PARTY" && p.patch.appVersion);
  const agents = cr.patches.filter((p) => p.patch.kind === "AGENT_UPGRADE" && p.patch.agentVersion);
  if (apps.length > 0) {
    const inventory = await tx.installedSoftware.findMany({ where: { tenantId, endpointId: d.endpointId }, select: { name: true, version: true } });
    const items = inventory.map((i) => ({ name: i.name, version: i.version ?? "" }));
    for (const { patch } of apps) {
      const v = patch.appVersion!;
      if (!isInstalledAtLeast(items, v.app.inventoryMatch, v.version)) return false;
    }
  }
  for (const { patch } of agents) {
    if (!d.endpoint.agentVersion || compareVersions(d.endpoint.agentVersion, patch.agentVersion!) < 0) return false;
  }
  return true;
}

/** Confirm (or time out) SENT deployments of one bank — optionally only these endpoints (fresh COLLECT). */
export async function confirmSentDeployments(tenantId: string, now = new Date(), endpointIds?: readonly string[]): Promise<{ succeeded: number; timedOut: number }> {
  let succeeded = 0;
  let timedOut = 0;
  let after: string | null = null;
  for (;;) {
    const cursor: string | null = after;
    const r = await withTenant(
      tenantId,
      async (tx) => {
        const rows = await loadSentChunk(tx, tenantId, cursor, endpointIds);
        const audits = new AuditBuffer();
        let ok = 0;
        let late = 0;
        for (const d of rows) {
          const started = d.startedAt ?? d.claimedAt ?? now;
          const fresh = d.endpoint.lastScanAt !== null && d.endpoint.lastScanAt >= started;
          if (fresh && (await windowsConfirmed(tx, tenantId, d.endpointId, d.targetGuids)) && (await packagesConfirmed(tx, tenantId, d, d.changeRequest))) {
            if (await finish(tx, tenantId, d.id, "SENT", "SUCCEEDED", null, { audits })) ok++;
          } else if (now.getTime() - started.getTime() > CONFIRM_TIMEOUT_MS) {
            if (await finish(tx, tenantId, d.id, "SENT", "TIMED_OUT", "install not confirmed by collected inventory within timeout", { kind: "INSTALL", audits })) late++;
          }
        }
        await audits.flush(tx);
        return { ok, late, last: rows.length === CONFIRM_CHUNK ? rows[rows.length - 1].id : null };
      },
      { timeoutMs: 60_000 },
    );
    succeeded += r.ok;
    timedOut += r.late;
    if (!r.last) break;
    after = r.last;
  }
  return { succeeded, timedOut };
}

/**
 * Worker step: (1) for SENT deployments without inventory newer than their start, queue COLLECT batches
 * on the endpoint's connector; (2) confirm / time out every connector bank's SENT deployments.
 */
export async function confirmConnectorDeployments(now = new Date()): Promise<{ collectJobs: number; succeeded: number; timedOut: number }> {
  const connectors = await withPlatform((tx) =>
    tx.connector.findMany({ where: { status: "ACTIVE", tenant: { active: true } }, select: { id: true, tenantId: true, lastSeenAt: true } }),
  );
  let collectJobs = 0;
  for (const c of connectors) {
    if (!isOnline(c.lastSeenAt, now)) continue;
    try {
      collectJobs += await withTenant(c.tenantId, async (tx) => {
        const sent = await tx.deployment.findMany({
          where: { tenantId: c.tenantId, status: "SENT", endpoint: { connectorId: c.id } },
          select: { startedAt: true, targetGuids: true, endpoint: { select: { id: true, tacticalAgentId: true, lastScanAt: true, ingestAttemptAt: true } } },
        });
        const due = new Map<string, { id: string; tacticalAgentId: string }>();
        for (const d of sent) {
          const started = d.startedAt ?? now;
          const e = d.endpoint;
          const stale = !e.lastScanAt || e.lastScanAt < started;
          // Packages are confirmed right away; Windows installs get time to run first.
          const settled = d.targetGuids.length === 0 || now.getTime() - started.getTime() >= WINDOWS_SETTLE_MS;
          const asked = e.ingestAttemptAt !== null && e.ingestAttemptAt >= started && now.getTime() - e.ingestAttemptAt.getTime() < RECOLLECT_EVERY_MS;
          if (stale && settled && !asked) due.set(e.id, { id: e.id, tacticalAgentId: e.tacticalAgentId });
        }
        const list = [...due.values()];
        let jobs = 0;
        for (let i = 0; i < list.length; i += MAX_AGENTS_PER_JOB) {
          await enqueueCollect(tx, c, list.slice(i, i + MAX_AGENTS_PER_JOB), now);
          jobs++;
        }
        return jobs;
      });
    } catch (err: unknown) {
      log.error("deploy.confirm_collect_failed", { connectorId: c.id, err });
    }
  }
  let succeeded = 0;
  let timedOut = 0;
  for (const tenantId of new Set(connectors.map((c) => c.tenantId))) {
    try {
      const r = await confirmSentDeployments(tenantId, now);
      succeeded += r.succeeded;
      timedOut += r.timedOut;
    } catch (err: unknown) {
      log.error("deploy.confirm_failed", { tenantId, err });
    }
  }
  return { collectJobs, succeeded, timedOut };
}
