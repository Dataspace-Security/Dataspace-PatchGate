import "server-only";
import { connect } from "node:tls";
import { cached, type Cached } from "./cache";
import type { CertOps } from "./types";

/**
 * Best-effort expiry of the certificate served at PUBLIC_BASE_URL (what connectors and browsers see).
 * Read-only probe: we only read the leaf certificate's notAfter, so verification is not required here.
 * Cached 1 h (failures 10 min). Prefer a blackbox probe from the monitoring network as well (RUNBOOK §8).
 */

const TIMEOUT_MS = 5_000;
const CACHE_MS = 60 * 60_000;
const ERROR_CACHE_MS = 10 * 60_000;
const DAY_MS = 86_400_000;

export function daysLeft(expiresAt: Date, now: Date): number {
  return Math.floor((expiresAt.getTime() - now.getTime()) / DAY_MS);
}

/** https URL → host/port to probe; null for anything else. */
export function probeTarget(url: string | undefined): { host: string; port: number } | null {
  if (!url) return null;
  try {
    const u = new URL(url);
    if (u.protocol !== "https:") return null;
    return { host: u.hostname, port: u.port ? Number(u.port) : 443 };
  } catch {
    return null;
  }
}

export function probeCertificate(host: string, port: number, timeoutMs = TIMEOUT_MS): Promise<CertOps> {
  return new Promise((resolve) => {
    const checkedAt = new Date();
    let settled = false;
    const done = (r: Omit<CertOps, "host" | "checkedAt">): void => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({ host, checkedAt, ...r });
    };
    const socket = connect({ host, port, servername: host, rejectUnauthorized: false, timeout: timeoutMs }, () => {
      const cert = socket.getPeerCertificate();
      const expiresAt = cert?.valid_to ? new Date(cert.valid_to) : null;
      if (!expiresAt || Number.isNaN(expiresAt.getTime())) return done({ expiresAt: null, daysLeft: null, error: "no certificate" });
      done({ expiresAt, daysLeft: daysLeft(expiresAt, new Date()), error: null });
    });
    socket.on("timeout", () => done({ expiresAt: null, daysLeft: null, error: "timeout" }));
    socket.on("error", (err: NodeJS.ErrnoException) => done({ expiresAt: null, daysLeft: null, error: (err.code ?? "error").slice(0, 40) }));
  });
}

const caches = new Map<string, Cached<CertOps>>();

/** Cached probe of PUBLIC_BASE_URL; null when no https base URL is configured. */
export async function publicCertStatus(publicBaseUrl: string | undefined): Promise<CertOps | null> {
  const t = probeTarget(publicBaseUrl);
  if (!t) return null;
  const key = `${t.host}:${t.port}`;
  let c = caches.get(key);
  if (!c) {
    c = cached(async () => {
      const r = await probeCertificate(t.host, t.port);
      if (r.error) throw Object.assign(new Error(r.error), { result: r }); // cache failures shorter
      return r;
    }, { ttlMs: CACHE_MS, errorTtlMs: ERROR_CACHE_MS });
    caches.set(key, c);
  }
  try {
    return await c.get();
  } catch (err: unknown) {
    const r = (err as { result?: CertOps }).result;
    return r ?? { host: t.host, expiresAt: null, daysLeft: null, error: "probe failed", checkedAt: new Date() };
  }
}
