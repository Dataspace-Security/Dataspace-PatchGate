import "server-only";
import { isOnline } from "@/lib/connector/policy";
import { currentWindow } from "@/lib/deploy/window";
import { withTenant, type Tx } from "@/lib/tenancy";
import { agentTarget, missingStateWhere } from "./common";
import { deploymentStage, installedVersionsFor, nextWindowStart, pcStatus, type JobStatus, type PcStatus, type Severity, type Stage } from "./story";

/**
 * One PC, as the operator needs it: who manages it, what is missing (Windows / apps / agent), what is fine,
 * and what PatchGate already tried on it. Everything is bounded by ONE PC (its own states and deployments).
 */

const INSTALL_TYPES = ["DEPLOY_WINDOWS", "DEPLOY_PACKAGE", "WU_INSTALL"] as const;
const UP_TO_DATE_LIMIT = 200;
const HISTORY_LIMIT = 20;
const SEVERITY_ORDER: Severity[] = ["CRITICAL", "IMPORTANT", "MODERATE", "LOW", "UNSPECIFIED"];

export interface MissingWindowsUpdate {
  patchId: string;
  kb: string | null;
  title: string;
  severity: Severity;
  failed: boolean;
  lastResult: string | null;
}

export interface AppNeedingUpdate {
  patchId: string;
  app: string;
  installed: string[];
  available: string;
  severity: Severity;
  failed: boolean;
}

export interface HistoryEntry {
  deploymentId: string;
  changeRequestId: string;
  title: string;
  when: Date | null;
  stage: Stage;
}

export interface EndpointDetail {
  endpoint: {
    id: string;
    hostname: string;
    site: string | null;
    client: string | null;
    osName: string | null;
    agentVersion: string | null;
    goarch: string | null;
    ringId: string | null;
    ringName: string | null;
    lastScanAt: Date | null;
    lastSeenAt: Date | null;
    lastWuScanAt: Date | null;
    lastWuScanError: string | null;
    rebootRequired: boolean;
    rebootRequiredAt: Date | null;
    createdAt: Date;
  };
  connector: { id: string; name: string; online: boolean; lastSeenAt: Date | null } | null;
  status: PcStatus;
  agentUpdate: { patchId: string; version: string } | null;
  windows: MissingWindowsUpdate[];
  apps: AppNeedingUpdate[];
  upToDate: { patchId: string; title: string; kb: string | null; kind: "WINDOWS" | "THIRD_PARTY" | "AGENT_UPGRADE" }[];
  upToDateTotal: number;
  softwareCount: number;
  history: HistoryEntry[];
  rings: { id: string; name: string }[];
}

const bySeverity = <T extends { severity: Severity; title?: string; app?: string }>(a: T, b: T) =>
  SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) || (a.title ?? a.app ?? "").localeCompare(b.title ?? b.app ?? "");

async function loadHistory(tx: Tx, tenantId: string, endpointId: string, connectorOnline: boolean | null, now: Date): Promise<HistoryEntry[]> {
  const deployments = await tx.deployment.findMany({
    where: { tenantId, endpointId },
    orderBy: { changeRequest: { createdAt: "desc" } },
    take: HISTORY_LIMIT,
    include: { changeRequest: { select: { id: true, title: true, createdAt: true, window: { select: { cron: true, durationMin: true, timezone: true } } } } },
  });
  const jobs = deployments.length
    ? await tx.connectorJob.findMany({
        where: { tenantId, deploymentId: { in: deployments.map((d) => d.id) }, type: { in: [...INSTALL_TYPES] } },
        orderBy: { createdAt: "desc" },
        select: { deploymentId: true, status: true, notBefore: true },
      })
    : [];
  return deployments.map((d) => {
    const job = jobs.find((j) => j.deploymentId === d.id) ?? null;
    const w = d.changeRequest.window;
    return {
      deploymentId: d.id,
      changeRequestId: d.changeRequest.id,
      title: d.changeRequest.title,
      when: d.finishedAt ?? d.startedAt ?? d.changeRequest.createdAt,
      stage: deploymentStage({
        status: d.status,
        note: d.note,
        error: d.error,
        failureKind: d.failureKind,
        windowOpen: w ? currentWindow(w, now) !== null : null,
        nextWindowAt: w ? nextWindowStart(w, now) : null,
        connectorOnline,
        job: job ? { status: job.status as JobStatus, notBefore: job.notBefore } : null,
        now,
      }),
    };
  });
}

/** null = no such PC in this bank (another bank's PC is "not found" too). */
export async function loadEndpointDetail(tenantId: string, endpointId: string, now = new Date()): Promise<EndpointDetail | null> {
  return withTenant(tenantId, async (tx) => {
    const e = await tx.endpoint.findFirst({
      where: { id: endpointId, tenantId },
      include: { ring: { select: { name: true } }, connector: { select: { id: true, name: true, lastSeenAt: true, status: true } } },
    });
    if (!e) return null;
    const connector = e.connector && e.connector.status === "ACTIVE" ? { id: e.connector.id, name: e.connector.name, lastSeenAt: e.connector.lastSeenAt, online: isOnline(e.connector.lastSeenAt, now) } : null;

    const missing = await tx.endpointPatchState.findMany({
      where: { ...missingStateWhere(tenantId), endpointId },
      include: { patch: { include: { appVersion: { include: { app: { select: { displayName: true, inventoryMatch: true } } } } } } },
    });
    const software = missing.some((s) => s.patch.kind === "THIRD_PARTY")
      ? await tx.installedSoftware.findMany({ where: { tenantId, endpointId }, select: { name: true, version: true } })
      : [];
    const installedWhere = { tenantId, endpointId, status: "INSTALLED" as const, patch: { supersededById: null } };
    const installed = await tx.endpointPatchState.findMany({
      where: installedWhere,
      take: UP_TO_DATE_LIMIT,
      orderBy: { updatedAt: "desc" },
      select: { patch: { select: { id: true, title: true, kb: true, kind: true } } },
    });
    const agent = await agentTarget(tx);
    const agentMissing = agent ? missing.find((s) => s.patchId === agent.patchId && s.status === "NEEDED") : undefined;

    const windows = missing
      .filter((s) => s.patch.kind === "WINDOWS")
      .map((s) => ({ patchId: s.patchId, kb: s.patch.kb, title: s.patch.title, severity: s.patch.severity, failed: s.status === "FAILED", lastResult: s.lastResult }))
      .sort(bySeverity);
    const apps = missing
      .filter((s) => s.patch.kind === "THIRD_PARTY" && s.patch.appVersion)
      .map((s) => ({
        patchId: s.patchId,
        app: s.patch.appVersion!.app.displayName,
        installed: installedVersionsFor(software, s.patch.appVersion!.app.inventoryMatch),
        available: s.patch.appVersion!.version,
        severity: s.patch.severity,
        failed: s.status === "FAILED",
      }))
      .sort(bySeverity);
    const critical = missing.filter((s) => s.patch.severity === "CRITICAL").length;

    return {
      endpoint: {
        id: e.id,
        hostname: e.hostname,
        site: e.site,
        client: e.client,
        osName: e.osName,
        agentVersion: e.agentVersion,
        goarch: e.goarch,
        ringId: e.ringId,
        ringName: e.ring?.name ?? null,
        lastScanAt: e.lastScanAt,
        lastSeenAt: e.lastSeenAt,
        lastWuScanAt: e.lastWuScanAt,
        lastWuScanError: e.lastWuScanError,
        rebootRequired: e.rebootRequired,
        rebootRequiredAt: e.rebootRequiredAt,
        createdAt: e.createdAt,
      },
      connector,
      status: pcStatus({ lastScanAt: e.lastScanAt, missing: missing.length, critical }),
      agentUpdate: agent && agentMissing ? agent : null,
      windows,
      apps,
      upToDate: installed.map((s) => ({ patchId: s.patch.id, title: s.patch.title, kb: s.patch.kb, kind: s.patch.kind })),
      upToDateTotal: installed.length < UP_TO_DATE_LIMIT ? installed.length : await tx.endpointPatchState.count({ where: installedWhere }),
      softwareCount: await tx.installedSoftware.count({ where: { tenantId, endpointId } }),
      history: await loadHistory(tx, tenantId, endpointId, connector ? connector.online : null, now),
      rings: await tx.ring.findMany({ where: { tenantId }, orderBy: { order: "asc" }, select: { id: true, name: true } }),
    };
  });
}
