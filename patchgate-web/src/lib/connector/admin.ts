import "server-only";
import { z } from "zod";
import { appendAudit } from "@/lib/audit/service";
import type { SessionUser } from "@/lib/auth/session";
import { env } from "@/lib/env";
import { DomainError } from "@/lib/errors";
import { requirePlatformAdmin, withPlatform, withTenant, isValidTenantId } from "@/lib/tenancy";
import { ENROLL_CODE_TTL_MS, enrollCodeHash, generateEnrollCode, siteNameSchema } from "./enroll";
import { jobKeyFingerprint, jobSigningPublicKey } from "./keys";
import { isOnline } from "./policy";
import { heartbeatSchema, type Heartbeat } from "./protocol";
import { BUNDLE_KEY_RE, bundleConfig, latestVersion } from "./site-bundle";
import { tacticalHealthView } from "./tactical-health-rules";

/**
 * Connector administration: platform admins create enrolment codes, revoke connectors and set the bank's
 * LAN limits. Bank users see their own bank's connectors read-only. Every change → the bank's audit chain.
 */

export const createEnrollmentSchema = z.object({
  tenantId: z.string().refine(isValidTenantId, "invalid bank id"),
  name: siteNameSchema,
});

export const updateLimitsSchema = z
  .object({
    maxConcurrentInstalls: z.number().int().min(1).max(1000).optional(),
    bandwidthLimitMbps: z.number().int().min(1).max(100_000).nullable().optional(),
  })
  .refine((v) => v.maxConcurrentInstalls !== undefined || v.bandwidthLimitMbps !== undefined, "nothing to change");

export interface CreatedEnrollment {
  code: string;
  tenantId: string;
  name: string;
  expiresAt: Date;
  serverUrl: string;
  initCommand: string;
  /** SHA-256 (hex) of the BANK's job-signing public key: the connector pins it at init (out-of-band check) */
  fingerprint: string;
  /** One-line web install for a fresh site VM (installers/site/web-install.md) */
  siteInstallCommand: string;
  /** Offline / USB alternative (bundle copied onto the VM) */
  usbInstallCommand: string;
  /** Site bundle served as "latest" (null = site bundles not configured on this platform) */
  bundleVersion: string | null;
}

/** `curl … /install/site.sh | sudo bash -s -- --code … --fingerprint …` (add --online on a VM with internet). */
export function siteInstallCommandFor(code: string, serverUrl: string, fingerprint: string): string {
  if (!/^[a-f0-9]{64}$/.test(fingerprint)) throw new Error("invalid job-key fingerprint");
  return `curl -fsSL ${new URL(serverUrl).origin}/install/site.sh | sudo bash -s -- --code ${code} --fingerprint ${fingerprint}`;
}

export function usbInstallCommandFor(code: string, serverUrl: string, fingerprint: string, bundleVersion: string | null, bundleKey: string | null = null): string {
  if (!/^[a-f0-9]{64}$/.test(fingerprint)) throw new Error("invalid job-key fingerprint");
  const v = bundleVersion ?? "<version>";
  // The bundle-signing key (server config) so a USB bundle's signature is checked too.
  const key = bundleKey && BUNDLE_KEY_RE.test(bundleKey) ? ` --bundle-key ${bundleKey}` : "";
  return `sudo ./install-site.sh --bundle patchgate-site-${v}.tar.gz${key} --server ${new URL(serverUrl).origin} --code ${code} --fingerprint ${fingerprint}`;
}

async function currentBundleVersion(): Promise<string | null> {
  const cfg = bundleConfig();
  return cfg ? latestVersion(cfg) : null;
}

/**
 * The exact command the bank's operator runs on the connector host (code via env: not in the process list).
 * It carries the fingerprint of the BANK's job-signing key, which the connector pins at init (no trust on
 * first use); the operator should still confirm the fingerprint out of band.
 */
export function initCommandFor(code: string, serverUrl: string, fingerprint: string): string {
  if (!/^[a-f0-9]{64}$/.test(fingerprint)) throw new Error("invalid job-key fingerprint");
  return [
    `PATCHGATE_ENROLL_CODE=${code} \\`,
    "  node patchgate-connector.mjs init --config /etc/patchgate-connector/connector.json \\",
    `       --server ${serverUrl} --ca /etc/patchgate-connector/patchgate-ca.pem \\`,
    `       --job-key-fingerprint ${fingerprint}`,
  ].join("\n");
}

/** Public URL connectors use: PUBLIC_BASE_URL, else (development) the origin the admin is using. */
export function connectorServerUrl(requestOrigin?: string): string {
  const configured = env().PUBLIC_BASE_URL;
  if (configured) return new URL(configured).origin;
  if (requestOrigin) return new URL(requestOrigin).origin;
  return "https://patchgate.example.com";
}

export async function createEnrollmentCode(user: SessionUser, input: unknown, requestOrigin?: string, now = new Date()): Promise<CreatedEnrollment> {
  requirePlatformAdmin(user);
  const { tenantId, name } = createEnrollmentSchema.parse(input);
  const code = generateEnrollCode();
  // The bank's own key (per bank with the remote signer); fails before a code is created if unusable.
  const fingerprint = jobKeyFingerprint(await jobSigningPublicKey(tenantId));
  const expiresAt = new Date(now.getTime() + ENROLL_CODE_TTL_MS);
  await withPlatform(async (tx) => {
    const tenant = await tx.tenant.findUnique({ where: { id: tenantId }, select: { active: true } });
    if (!tenant) throw new DomainError("Bank not found", 404);
    if (!tenant.active) throw new DomainError("This bank is deactivated", 409);
    // Older unused codes for the same site are withdrawn: only the newest one works.
    await tx.connectorEnrollment.updateMany({ where: { tenantId, name, usedAt: null, expiresAt: { gt: now } }, data: { expiresAt: now } });
    await tx.connectorEnrollment.create({ data: { id: enrollCodeHash(code), tenantId, name, createdBy: user.upn, expiresAt } });
    await appendAudit(
      {
        tenantId,
        actor: user.upn,
        action: "connector.enrollment_created",
        entity: "ConnectorEnrollment",
        entityId: enrollCodeHash(code).slice(0, 16), // never the code itself
        payload: { name, expiresAt: expiresAt.toISOString(), jobKeyFingerprint: fingerprint },
      },
      tx,
    );
  });
  const serverUrl = connectorServerUrl(requestOrigin);
  const bundleVersion = await currentBundleVersion();
  return {
    code,
    tenantId,
    name,
    expiresAt,
    serverUrl,
    initCommand: initCommandFor(code, serverUrl, fingerprint),
    fingerprint,
    siteInstallCommand: siteInstallCommandFor(code, serverUrl, fingerprint),
    usbInstallCommand: usbInstallCommandFor(code, serverUrl, fingerprint, bundleVersion, bundleConfig()?.pubkey ?? null),
    bundleVersion,
  };
}

async function loadConnectorForAdmin(connectorId: string) {
  const c = await withPlatform((tx) => tx.connector.findUnique({ where: { id: connectorId }, select: { id: true, tenantId: true, name: true, status: true } }));
  if (!c) throw new DomainError("Connector not found", 404);
  return c;
}

/** Revoke: every further request of that connector is rejected (403); queued jobs are cancelled. */
export async function revokeConnector(user: SessionUser, connectorId: string, reason?: string): Promise<{ cancelledJobs: number }> {
  requirePlatformAdmin(user);
  const c = await loadConnectorForAdmin(connectorId);
  if (c.status === "REVOKED") throw new DomainError("Connector is already revoked", 409);
  return withTenant(c.tenantId, async (tx) => {
    const { count } = await tx.connector.updateMany({ where: { id: c.id, tenantId: c.tenantId, status: "ACTIVE" }, data: { status: "REVOKED" } });
    if (count !== 1) throw new DomainError("Connector was modified concurrently", 409);
    const cancelled = await tx.connectorJob.updateMany({
      where: { connectorId: c.id, tenantId: c.tenantId, status: { in: ["QUEUED", "DELIVERED"] } },
      data: { status: "CANCELLED", error: "connector revoked", completedAt: new Date() },
    });
    // Deployments that were waiting on this connector go back to the queue (another connector may take the PCs over).
    await tx.deployment.updateMany({
      where: { tenantId: c.tenantId, status: "SENDING", endpoint: { connectorId: c.id } },
      data: { status: "QUEUED", claimedAt: null, note: "connector revoked; waiting for a connector" },
    });
    await appendAudit(
      {
        tenantId: c.tenantId,
        actor: user.upn,
        action: "connector.revoked",
        entity: "Connector",
        entityId: c.id,
        payload: { name: c.name, reason: reason?.slice(0, 500) ?? null, cancelledJobs: cancelled.count },
      },
      tx,
    );
    return { cancelledJobs: cancelled.count };
  });
}

export async function updateConnectorLimits(user: SessionUser, connectorId: string, input: unknown) {
  requirePlatformAdmin(user);
  const changes = updateLimitsSchema.parse(input);
  const c = await loadConnectorForAdmin(connectorId);
  return withTenant(c.tenantId, async (tx) => {
    const before = await tx.connector.findUniqueOrThrow({ where: { id: c.id }, select: { maxConcurrentInstalls: true, bandwidthLimitMbps: true } });
    const after = await tx.connector.update({
      where: { id: c.id },
      data: changes,
      select: { maxConcurrentInstalls: true, bandwidthLimitMbps: true },
    });
    await appendAudit(
      { tenantId: c.tenantId, actor: user.upn, action: "connector.limits_updated", entity: "Connector", entityId: c.id, payload: { name: c.name, before, after } },
      tx,
    );
    return { id: c.id, ...after };
  });
}

// ---------------------------------------------------------------------------------------------
// Read models (UI)
// ---------------------------------------------------------------------------------------------

export interface ConnectorView {
  id: string;
  tenantId: string;
  tenantName: string;
  name: string;
  status: "ACTIVE" | "REVOKED";
  online: boolean;
  version: string | null;
  enrolledAt: Date;
  lastSeenAt: Date | null;
  cacheBaseUrl: string | null;
  maxConcurrentInstalls: number;
  bandwidthLimitMbps: number | null;
  heartbeat: Heartbeat | null;
  endpoints: number;
  queuedJobs: number;
  inFlightJobs: number;
  failedJobs24h: number;
}

/** Parse a stored heartbeat defensively (older rows / partial bodies → null). */
export function storedHeartbeat(v: unknown): Heartbeat | null {
  const r = heartbeatSchema.safeParse(v);
  return r.success ? r.data : null;
}

type ListScope = { kind: "platform" } | { kind: "tenant"; tenantId: string };

/** Connectors with health + queue counters. Platform admins: every bank; bank users: their own. */
export async function listConnectors(scope: ListScope, now = new Date()): Promise<ConnectorView[]> {
  const run = async (tx: Parameters<Parameters<typeof withPlatform>[0]>[0]) => {
    const where = scope.kind === "tenant" ? { tenantId: scope.tenantId } : {};
    const rows = await tx.connector.findMany({
      where,
      orderBy: [{ tenant: { name: "asc" } }, { name: "asc" }],
      include: { tenant: { select: { name: true } }, _count: { select: { endpoints: true } } },
    });
    const ids = rows.map((r) => r.id);
    const counts = ids.length
      ? await tx.connectorJob.groupBy({ by: ["connectorId", "status"], where: { connectorId: { in: ids }, status: { in: ["QUEUED", "DELIVERED"] } }, _count: { _all: true } })
      : [];
    const failed = ids.length
      ? await tx.connectorJob.groupBy({
          by: ["connectorId"],
          where: { connectorId: { in: ids }, status: "FAILED", completedAt: { gt: new Date(now.getTime() - 24 * 60 * 60_000) } },
          _count: { _all: true },
        })
      : [];
    return rows.map((r): ConnectorView => {
      const n = (s: string) => counts.find((c) => c.connectorId === r.id && c.status === s)?._count._all ?? 0;
      return {
        id: r.id,
        tenantId: r.tenantId,
        tenantName: r.tenant.name,
        name: r.name,
        status: r.status,
        online: r.status === "ACTIVE" && isOnline(r.lastSeenAt, now),
        version: r.version,
        enrolledAt: r.enrolledAt,
        lastSeenAt: r.lastSeenAt,
        cacheBaseUrl: r.cacheBaseUrl,
        maxConcurrentInstalls: r.maxConcurrentInstalls,
        bandwidthLimitMbps: r.bandwidthLimitMbps,
        heartbeat: storedHeartbeat(r.heartbeat),
        endpoints: r._count.endpoints,
        queuedJobs: n("QUEUED"),
        inFlightJobs: n("DELIVERED"),
        failedJobs24h: failed.find((f) => f.connectorId === r.id)?._count._all ?? 0,
      };
    });
  };
  return scope.kind === "tenant" ? withTenant(scope.tenantId, run) : withPlatform(run);
}

/** Pending (unused, unexpired) enrolment codes — metadata only, never the code. */
export async function listPendingEnrollments(now = new Date()) {
  return withPlatform((tx) =>
    tx.connectorEnrollment.findMany({
      where: { usedAt: null, expiresAt: { gt: now } },
      orderBy: { createdAt: "desc" },
      take: 50,
      select: { id: true, name: true, createdBy: true, expiresAt: true, tenant: { select: { name: true } } },
    }),
  );
}

/** Banks a platform admin can create codes for. */
export async function listActiveBanks() {
  return withPlatform((tx) => tx.tenant.findMany({ where: { active: true }, orderBy: { name: "asc" }, select: { id: true, name: true } }));
}

/** Dashboard card: this bank's connector health. */
export async function connectorHealth(tenantId: string, now = new Date()) {
  const list = await listConnectors({ kind: "tenant", tenantId }, now);
  const active = list.filter((c) => c.status === "ACTIVE");
  return {
    total: active.length,
    online: active.filter((c) => c.online).length,
    offline: active.filter((c) => !c.online),
    tacticalDown: active.filter((c) => c.online && c.heartbeat && !c.heartbeat.tactical.reachable && tacticalHealthView(c.heartbeat)?.state !== "natsdown"),
    // Tactical answers but cannot reach its NATS message bus (heartbeat.tacticalHealth): no PC reachable.
    tacticalMessagingDown: active.filter((c) => c.online && tacticalHealthView(c.heartbeat)?.state === "natsdown"),
    queuedJobs: active.reduce((s, c) => s + c.queuedJobs, 0),
    failedJobs24h: active.reduce((s, c) => s + c.failedJobs24h, 0),
  };
}
