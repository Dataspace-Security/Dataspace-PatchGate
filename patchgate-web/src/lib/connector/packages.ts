import "server-only";
import { realpath, stat } from "node:fs/promises";
import { resolve, sep } from "node:path";
import { appendAudit } from "@/lib/audit/service";
import { env } from "@/lib/env";
import { withTenant, type Tx } from "@/lib/tenancy";
import type { AuthedConnector } from "./auth";
import { ConnectorApiError } from "./errors";

/**
 * GET /api/connector/v1/packages/{sha256} — a site cache downloads a package ONCE from PatchGate.
 *
 * Served only when THIS connector's bank is entitled to the exact bytes (by SHA-256):
 *  1. a VERIFIED third-party AppVersion the bank has enabled (TenantApp) or that belongs to one of the
 *     bank's approved / deploying change requests;
 *  2. a VERIFIED Tactical agent build from the mirror (shared, admin-approved);
 *  3. a Microsoft update file / offline scan catalog the winupdate pipeline handed to this connector
 *     (a CACHE_PACKAGE job for this connector names it — those are only created from hooks.ts output).
 * Anything else is a 404 (permanent for the connector) — a bank can never pull another bank's package.
 * Files are resolved inside REPO_DIR with realpath containment; only pkgs/, tactical/, winupdate/ are servable.
 */

const SHA256_RE = /^[a-f0-9]{64}$/;
const SERVABLE_ROOTS = new Set(["pkgs", "tactical", "winupdate"]);
// Alphanumeric first and last char: no ".", "..", dot-dirs (.tmp, .pending, .keys) or trailing-dot aliases.
const SEGMENT = /^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9_-])?$/;
const CR_LIVE = ["APPROVED", "DEPLOYING", "COMPLETED", "PARTIAL"] as const;

export interface EntitledPackage {
  sha256: string;
  repoPath: string;
  source: "app" | "agent" | "winupdate";
}

export function assertServableRepoPath(rel: string): string {
  const segs = rel.split("/");
  if (segs.length < 2 || segs.length > 10 || !segs.every((s) => SEGMENT.test(s)) || !SERVABLE_ROOTS.has(segs[0])) {
    throw new ConnectorApiError(404, "unknown package");
  }
  return rel;
}

/** Absolute, symlink-resolved path that is guaranteed to stay inside the repository root. */
export async function servableFile(root: string, rel: string): Promise<string> {
  const base = resolve(root);
  const abs = resolve(base, assertServableRepoPath(rel));
  if (!abs.startsWith(base + sep)) throw new ConnectorApiError(404, "unknown package");
  const [realRoot, realFile] = await Promise.all([realpath(base), realpath(abs)]);
  if (!realFile.startsWith(realRoot + sep)) throw new ConnectorApiError(404, "unknown package");
  return realFile;
}

export async function findEntitlement(tx: Tx, tenantId: string, connectorId: string, sha256: string): Promise<EntitledPackage | null> {
  const app = await tx.appVersion.findFirst({
    where: {
      sha256,
      verification: "VERIFIED",
      repoPath: { not: null },
      OR: [
        { app: { tenants: { some: { tenantId } } } },
        { patch: { requests: { some: { changeRequest: { tenantId, status: { in: [...CR_LIVE] } } } } } },
      ],
    },
    select: { repoPath: true },
  });
  if (app?.repoPath) return { sha256, repoPath: app.repoPath, source: "app" };

  const agent = await tx.mirroredRelease.findFirst({ where: { sha256, component: "TACTICAL_AGENT", verification: "VERIFIED" }, select: { repoPath: true } });
  if (agent) return { sha256, repoPath: agent.repoPath, source: "agent" };

  const wu = await tx.connectorJob.findFirst({
    where: { connectorId, tenantId, type: "CACHE_PACKAGE", status: { not: "CANCELLED" }, payload: { path: ["package", "sha256"], equals: sha256 } },
    orderBy: { createdAt: "desc" },
    select: { payload: true },
  });
  const repoPath = (wu?.payload as { package?: { repoPath?: unknown } } | undefined)?.package?.repoPath;
  if (typeof repoPath === "string" && repoPath.startsWith("winupdate/")) return { sha256, repoPath, source: "winupdate" };
  return null;
}

export interface PackageDownload {
  path: string;
  size: number;
  repoPath: string;
}

/** Resolve (and audit) a package download for an authenticated connector. */
export async function resolvePackageDownload(connector: AuthedConnector, sha256: string): Promise<PackageDownload> {
  if (!SHA256_RE.test(sha256)) throw new ConnectorApiError(404, "unknown package");
  const entitled = await withTenant(connector.tenantId, (tx) => findEntitlement(tx, connector.tenantId, connector.id, sha256));
  if (!entitled) throw new ConnectorApiError(404, "unknown package");
  let path: string;
  let size: number;
  try {
    path = await servableFile(env().REPO_DIR, entitled.repoPath);
    const s = await stat(path);
    if (!s.isFile()) throw new Error("not a file");
    size = s.size;
  } catch {
    throw new ConnectorApiError(404, "unknown package");
  }
  await appendAudit({
    tenantId: connector.tenantId,
    actor: `connector:${connector.id}`,
    action: "connector.package_downloaded",
    entity: "Package",
    entityId: sha256,
    payload: { repoPath: entitled.repoPath, size, source: entitled.source },
  });
  return { path, size, repoPath: entitled.repoPath };
}
