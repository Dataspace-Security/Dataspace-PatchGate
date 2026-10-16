import { randomUUID } from "node:crypto";
import { mkdir, readFile, rm, statfs, writeFile } from "node:fs/promises";
import { connect as tcpConnect, type Socket } from "node:net";
import { join } from "node:path";
import { connect as tlsConnect, createSecureContext } from "node:tls";
import { loadTacticalApiKey, requireEnrolled, type ConnectorConfig } from "./config.ts";
import { keyFileTooOpen, loadPrivateKey } from "./keys.ts";
import { createPatchGateClient } from "./pg-client.ts";
import { parseSiemUrl } from "./siem/syslog.ts";
import { createTacticalClient } from "./tactical/client.ts";
import { errorMessage } from "./util/log.ts";

/**
 * `check`: one-shot health probe for monitoring. Prints one JSON line per check and returns the
 * exit code (0 = all good, 1 = at least one check failed).
 */

export interface CheckResult {
  check: string;
  ok: boolean;
  detail?: string;
}

async function probe(name: string, fn: () => Promise<string | undefined>): Promise<CheckResult> {
  try {
    const detail = await fn();
    return { check: name, ok: true, ...(detail ? { detail } : {}) };
  } catch (err) {
    return { check: name, ok: false, detail: errorMessage(err).slice(0, 500) };
  }
}

async function writable(dir: string): Promise<void> {
  await mkdir(dir, { recursive: true });
  const f = join(dir, `.check-${randomUUID()}`);
  await writeFile(f, "ok", { mode: 0o600 });
  await rm(f, { force: true });
}

function siemConnect(url: string, ca: Buffer | undefined): Promise<void> {
  const t = parseSiemUrl(url);
  return new Promise((resolve, reject) => {
    const s: Socket =
      t.protocol === "tls"
        ? tlsConnect({ host: t.host, port: t.port, servername: t.host, ca, rejectUnauthorized: true }, () => {
            s.end();
            resolve();
          })
        : tcpConnect({ host: t.host, port: t.port }, () => {
            s.end();
            resolve();
          });
    s.setTimeout(10_000, () => s.destroy(new Error("SIEM connect timed out")));
    s.once("error", reject);
  });
}

/** Read-only view of the cache index (the running service owns the file; never rewrite it here). */
async function cacheStats(stateDir: string): Promise<{ files: number; bytes: number; freeBytes: null }> {
  try {
    const parsed = JSON.parse(await readFile(join(stateDir, "cache-index.json"), "utf8")) as { entries?: Array<{ size?: unknown }> };
    const entries = Array.isArray(parsed.entries) ? parsed.entries : [];
    const bytes = entries.reduce((n, e) => n + (typeof e.size === "number" && e.size > 0 ? Math.trunc(e.size) : 0), 0);
    return { files: entries.length, bytes, freeBytes: null };
  } catch {
    return { files: 0, bytes: 0, freeBytes: null };
  }
}

export async function runChecks(cfg: ConnectorConfig, version: string): Promise<CheckResult[]> {
  const results: CheckResult[] = [{ check: "config", ok: true }];
  const enrolled = await probe("enrolled", async () => {
    const e = requireEnrolled(cfg);
    await loadPrivateKey(e.identity.privateKeyFile);
    if (await keyFileTooOpen(e.identity.privateKeyFile)) throw new Error("private key file is readable by group/other (chmod 600)");
    return `connector ${e.identity.connectorId}`;
  });
  results.push(enrolled);
  results.push(await probe("stateDir", async () => writable(cfg.stateDir).then(() => cfg.stateDir)));
  const cacheDir = cfg.cache.dir ?? join(cfg.stateDir, "cache");
  results.push(
    await probe("cacheDir", async () => {
      await writable(cacheDir);
      const fs = await statfs(cacheDir);
      const free = Number(fs.bavail) * Number(fs.bsize);
      if (free < cfg.cache.minFreeBytes) throw new Error(`only ${free} bytes free (< minFreeBytes ${cfg.cache.minFreeBytes})`);
      return `${free} bytes free`;
    }),
  );
  if (cfg.cache.tls) {
    const tls = cfg.cache.tls;
    results.push(
      await probe("cacheTls", async () => {
        createSecureContext({ cert: await readFile(tls.certFile), key: await readFile(tls.keyFile) });
        return undefined;
      }),
    );
  }
  results.push(
    await probe("tactical", async () => {
      const t = createTacticalClient({
        baseUrl: cfg.tactical.url,
        apiKey: await loadTacticalApiKey(cfg),
        timeoutMs: cfg.tactical.timeoutMs,
        ca: cfg.tactical.caFile ? await readFile(cfg.tactical.caFile) : undefined,
      });
      const agents = await t.listAgents();
      if (!cfg.tactical.installScriptId) return `${agents.length} agents (warning: tactical.installScriptId not set; DEPLOY_PACKAGE will fail)`;
      return `${agents.length} agents`;
    }),
  );
  if (enrolled.ok) {
    const e = requireEnrolled(cfg);
    results.push(
      await probe("patchgate", async () => {
        const pg = createPatchGateClient({
          serverUrl: e.server.url,
          ca: e.server.caFile ? await readFile(e.server.caFile) : undefined,
          connectorId: e.identity.connectorId,
          privateKey: await loadPrivateKey(e.identity.privateKeyFile),
          timeoutMs: e.server.requestTimeoutMs,
        });
        const r = await pg.heartbeat({
          version,
          cacheBaseUrl: cfg.cache.baseUrl,
          cache: await cacheStats(cfg.stateDir),
          tactical: { reachable: results.find((x) => x.check === "tactical")?.ok ?? false, agents: null, error: null },
        });
        const skew = Date.parse(r.serverTime) - Date.now();
        if (Number.isFinite(skew) && Math.abs(skew) > 120_000) throw new Error(`clock skew ${skew} ms with PatchGate`);
        return `heartbeat accepted (maxConcurrentInstalls ${r.maxConcurrentInstalls}, bandwidthLimitMbps ${r.bandwidthLimitMbps ?? "none"})`;
      }),
    );
  }
  if (cfg.siem) {
    const siem = cfg.siem;
    results.push(await probe("siem", async () => siemConnect(siem.url, siem.caFile ? await readFile(siem.caFile) : undefined).then(() => siem.url)));
  }
  return results;
}
