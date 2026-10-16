// Write / refresh lab/connector/bank-a/etc/connector.json from the Tactical provisioning output.
// Operator-owned sections (tactical, cache, limits, siem) are rewritten; `server` + `identity` written by
// `init` are preserved. Usage: node lab/connector/write-config.mjs
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const domain = process.env.LAB_DOMAIN ?? "patchgate-lab.internal";
const prov = JSON.parse(readFileSync(join(here, "..", "tactical", "provision.json"), "utf8"));
const file = join(here, "bank-a", "etc", "connector.json");
// Bank-held trust policy (defence in depth against a compromised platform): which publishers / agent builds
// this site will ever cache or install. Generated once by up.sh; the bank edits it, PatchGate cannot.
const trustFile = join(here, "bank-a", "trust-policy.json");
const trust = existsSync(trustFile) ? JSON.parse(readFileSync(trustFile, "utf8")) : undefined;
const current = existsSync(file) ? JSON.parse(readFileSync(file, "utf8")) : {};
const ETC = "/etc/patchgate-connector";
const MiB = 1024 ** 2;

const next = {
  stateDir: "/var/lib/patchgate-connector",
  logLevel: process.env.PGC_LOG_LEVEL ?? "info",
  ...(current.insecureDev !== undefined ? { insecureDev: current.insecureDev } : {}),
  ...(current.server ? { server: current.server } : {}),
  ...(current.identity ? { identity: current.identity } : {}),
  tactical: {
    url: `https://api.${domain}:4443`, // Tactical nginx listens on 4443 inside the bank LAN
    apiKeyFile: `${ETC}/tactical-api-key`,
    caFile: `${ETC}/bank-ca.pem`,
    installScriptId: prov.installScriptId,
    wuScanScriptId: prov.wuScanScriptId,
    wuInstallScriptId: prov.wuInstallScriptId,
    timeoutMs: 30000,
    statusIntervalSec: 60,
    maxParallelCalls: 8,
  },
  cache: {
    baseUrl: `https://pg-cache.${domain}:8443/repo`,
    listenHost: "0.0.0.0",
    port: 8443,
    tls: { certFile: `${ETC}/cache-cert.pem`, keyFile: `${ETC}/cache-key.pem` },
    maxPackageBytes: 4 * 1024 ** 3,
    minFreeBytes: 512 * MiB,
    maxConcurrentDownloads: 50,
    perClientConcurrency: 2, // NB lab: every PC arrives via the socat ingress, i.e. from ONE client IP
    bandwidthLimitMbps: 200,
    retryAfterSec: 30,
  },
  limits: {
    maxConcurrentInstalls: 50,
    maxConcurrentOtherJobs: 4,
    maxQueuedJobs: 200,
    heartbeatIntervalSec: 60,
    pollWaitSec: 25,
    shutdownGraceSec: 60,
    journalRetentionDays: 30,
  },
  ...(trust ? { trust } : {}),
  siem: {
    url: `tls://siem.${domain}:6514`,
    caFile: `${ETC}/bank-ca.pem`,
    hostname: "bank-a-connector-hq",
    pollIntervalSec: 30,
    batchSize: 500,
  },
};
writeFileSync(file, JSON.stringify(next, null, 2) + "\n");
console.log(`wrote ${file}${next.identity ? ` (enrolled as ${next.identity.connectorId})` : " (not enrolled yet)"}`);
