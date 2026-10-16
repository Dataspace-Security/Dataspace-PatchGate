// Writes /etc/patchgate-connector/connector.json for a bank site (run by install-site.sh inside the connector
// image: `node write-config.mjs`). Operator-owned sections (tactical, cache, limits, siem) are (re)written
// from the environment; `server` + `identity` (written by `patchgate-connector init`), `insecureDev` and a
// bank-held `trust` policy are preserved, so re-running the installer never breaks the enrolment.
//
// Env: PGC_ETC (default /etc/patchgate-connector), SITE_DOMAIN, CACHE_PORT, INSTALL_SCRIPT_ID, WU_SCAN_SCRIPT_ID,
//      WU_INSTALL_SCRIPT_ID, SIEM_URL (optional tls://host:port), SIEM_HOSTNAME (optional), LOG_LEVEL.
import { existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const etc = process.env.PGC_ETC ?? "/etc/patchgate-connector";
const file = join(etc, "connector.json");
const need = (k) => {
  const v = process.env[k];
  if (!v) throw new Error(`write-config: ${k} is required`);
  return v;
};
const int = (k) => {
  const n = Number(need(k));
  if (!Number.isInteger(n) || n <= 0) throw new Error(`write-config: ${k} must be a positive integer`);
  return n;
};

const domain = need("SITE_DOMAIN");
if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(domain)) throw new Error("write-config: invalid SITE_DOMAIN");
const cachePort = int("CACHE_PORT");
const current = existsSync(file) ? JSON.parse(readFileSync(file, "utf8")) : {};
const MiB = 1024 ** 2;
const siemUrl = process.env.SIEM_URL ?? "";

const next = {
  stateDir: "/var/lib/patchgate-connector",
  logLevel: process.env.LOG_LEVEL ?? current.logLevel ?? "info",
  ...(current.insecureDev !== undefined ? { insecureDev: current.insecureDev } : {}),
  ...(current.server ? { server: current.server } : {}),
  ...(current.identity ? { identity: current.identity } : {}),
  tactical: {
    url: `https://api.${domain}:4443`, // Tactical nginx on the site LAN (container network)
    apiKeyFile: `${etc}/tactical-api-key`,
    caFile: `${etc}/bank-ca.pem`,
    installScriptId: int("INSTALL_SCRIPT_ID"),
    wuScanScriptId: int("WU_SCAN_SCRIPT_ID"),
    wuInstallScriptId: int("WU_INSTALL_SCRIPT_ID"),
    timeoutMs: 30000,
    statusIntervalSec: 300,
    maxParallelCalls: 8,
    ...(current.tactical?.installScriptTimeoutSec ? { installScriptTimeoutSec: current.tactical.installScriptTimeoutSec } : {}),
  },
  cache: {
    baseUrl: `https://pg-cache.${domain}${cachePort === 443 ? "" : `:${cachePort}`}/repo`,
    listenHost: "0.0.0.0",
    port: 8443,
    tls: { certFile: `${etc}/cache-cert.pem`, keyFile: `${etc}/cache-key.pem` },
    maxPackageBytes: 4 * 1024 ** 3,
    minFreeBytes: current.cache?.minFreeBytes ?? 1024 * MiB,
    maxCacheBytes: current.cache?.maxCacheBytes ?? 50 * 1024 ** 3,
    maxConcurrentDownloads: current.cache?.maxConcurrentDownloads ?? 50,
    perClientConcurrency: current.cache?.perClientConcurrency ?? 2,
    bandwidthLimitMbps: current.cache?.bandwidthLimitMbps ?? 200,
    retryAfterSec: 30,
  },
  limits: current.limits ?? {
    maxConcurrentInstalls: 50,
    maxConcurrentOtherJobs: 4,
    maxQueuedJobs: 200,
    heartbeatIntervalSec: 60,
    pollWaitSec: 25,
    shutdownGraceSec: 60,
    journalRetentionDays: 30,
  },
  ...(current.trust ? { trust: current.trust } : {}),
  ...(siemUrl
    ? {
        siem: {
          url: siemUrl,
          caFile: `${etc}/bank-ca.pem`,
          hostname: process.env.SIEM_HOSTNAME || `patchgate-connector-${domain}`,
          pollIntervalSec: 30,
          batchSize: 500,
        },
      }
    : {}),
};
const tmp = `${file}.tmp-${process.pid}`;
writeFileSync(tmp, JSON.stringify(next, null, 2) + "\n", { mode: 0o640 });
renameSync(tmp, file);
console.log(`connector.json written (${next.identity ? `enrolled as ${next.identity.connectorId}` : "not enrolled yet"})`);
