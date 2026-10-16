import { readFile, mkdir } from "node:fs/promises";
import { hostname } from "node:os";
import { join } from "node:path";
import { CacheDownloader, volumeFreeBytes } from "./cache/download.ts";
import { CacheIndex } from "./cache/cache-index.ts";
import { CacheServer } from "./cache/server.ts";
import { cachePathPrefix, loadTacticalApiKey, type EnrolledConfig } from "./config.ts";
import { TacticalGuard } from "./guard/tactical-guard.ts";
import { JobRunner } from "./jobs/runner.ts";
import { Journal } from "./journal.ts";
import { loadPrivateKey } from "./keys.ts";
import { createPatchGateClient, PatchGateError, type HeartbeatResponse, type PatchGateClient } from "./pg-client.ts";
import type { Heartbeat } from "./protocol.ts";
import { SiemRelay } from "./siem/relay.ts";
import { parseSiemUrl } from "./siem/syslog.ts";
import { createTacticalClient, type TacticalClient } from "./tactical/client.ts";
import { AbortedError, backoffDelay, sleep } from "./util/backoff.ts";
import { sweepAtomicTemps } from "./util/fsx.ts";
import { errorMessage, type Logger } from "./util/log.ts";
import { Semaphore } from "./util/semaphore.ts";
import { mbpsToBytesPerSec, TokenBucket } from "./util/token-bucket.ts";

/**
 * The connector service: heartbeat loop, job long-poll loop, job runner, package cache server and
 * (optional) SIEM relay. All network traffic to PatchGate is outbound.
 */

const DEFAULT_INSTALLS_BEFORE_FIRST_HEARTBEAT = 5;

export interface ServiceHandle {
  stop(): Promise<void>;
  readonly runner: JobRunner;
  readonly cacheServer: CacheServer;
  readonly index: CacheIndex;
  readonly cachePort: number;
  readonly guard: TacticalGuard;
  /** Current effective limits (after heartbeat). */
  limits(): { maxConcurrentInstalls: number; bandwidthLimitMbps: number | null };
  /** Send one heartbeat now (tests / check). */
  heartbeatNow(): Promise<HeartbeatResponse | null>;
}

export interface ServiceOptions {
  log: Logger;
  version: string;
  /** Test hooks */
  pg?: PatchGateClient;
  tactical?: TacticalClient;
}

const minNonNull = (...v: Array<number | null | undefined>): number | null => {
  const n = v.filter((x): x is number => typeof x === "number");
  return n.length ? Math.min(...n) : null;
};

async function readOptional(path: string | undefined): Promise<Buffer | undefined> {
  return path ? readFile(path) : undefined;
}

export async function startService(cfg: EnrolledConfig, opts: ServiceOptions): Promise<ServiceHandle> {
  const log = opts.log.child({ connectorId: cfg.identity.connectorId });
  await mkdir(cfg.stateDir, { recursive: true, mode: 0o700 });
  const cacheDir = cfg.cache.dir ?? join(cfg.stateDir, "cache");
  await mkdir(cacheDir, { recursive: true });
  const swept = await sweepAtomicTemps(cfg.stateDir);
  if (swept) log.info("stale temp files removed from stateDir", { count: swept });

  const privateKey = await loadPrivateKey(cfg.identity.privateKeyFile);
  const pg =
    opts.pg ??
    createPatchGateClient({
      serverUrl: cfg.server.url,
      ca: await readOptional(cfg.server.caFile),
      connectorId: cfg.identity.connectorId,
      privateKey,
      timeoutMs: cfg.server.requestTimeoutMs,
    });
  const tactical =
    opts.tactical ??
    createTacticalClient({
      baseUrl: cfg.tactical.url,
      apiKey: await loadTacticalApiKey(cfg),
      timeoutMs: cfg.tactical.timeoutMs,
      ca: await readOptional(cfg.tactical.caFile),
    });

  const journal = await Journal.open(join(cfg.stateDir, "journal.jsonl"), {
    retentionDays: cfg.limits.journalRetentionDays,
    maxBytes: cfg.limits.journalMaxBytes,
    log: log.child({ component: "journal" }),
  });
  if (journal.skippedLines) log.warn("journal had unreadable lines (skipped)", { skipped: journal.skippedLines });
  const index = await CacheIndex.open(join(cfg.stateDir, "cache-index.json"), cacheDir, log);

  const localBw = cfg.cache.bandwidthLimitMbps;
  const cacheBucket = new TokenBucket(localBw ? mbpsToBytesPerSec(localBw) : null);
  const downloadBucket = cfg.server.downloadLimitMbps ? new TokenBucket(mbpsToBytesPerSec(cfg.server.downloadLimitMbps)) : undefined;
  const installCeiling = Math.min(cfg.limits.maxConcurrentInstalls, cfg.cache.maxConcurrentDownloads);
  const deploySem = new Semaphore(Math.min(DEFAULT_INSTALLS_BEFORE_FIRST_HEARTBEAT, installCeiling));
  const otherSem = new Semaphore(cfg.limits.maxConcurrentOtherJobs);
  let effective = { maxConcurrentInstalls: deploySem.capacity, bandwidthLimitMbps: localBw };

  let agentCount: number | null = null;
  const downloader = new CacheDownloader({
    pg,
    index,
    root: cacheDir,
    maxPackageBytes: cfg.cache.maxPackageBytes,
    minFreeBytes: cfg.cache.minFreeBytes,
    maxCacheBytes: cfg.cache.maxCacheBytes,
    bucket: downloadBucket,
    log,
  });
  await downloader.sweepTmp(); // nothing is downloading yet: every file in <cache>/.tmp is a crash leftover
  const evictNow = async () => {
    try {
      const r = await downloader.makeRoom(0); // keep the cache under cache.maxCacheBytes and above minFreeBytes
      if (r.stillOver) log.warn("cache over cache.maxCacheBytes or below cache.minFreeBytes; every remaining package is pinned by an unexpired job or being downloaded");
    } catch (err) {
      log.warn("cache eviction failed", { error: errorMessage(err) });
    }
  };
  await evictNow();
  const guard = await TacticalGuard.open({
    tactical,
    pg,
    stateFile: join(cfg.stateDir, "tactical-guard.json"),
    intervalMs: cfg.tactical.guardIntervalSec * 1000,
    maxAgentReadsPerTick: cfg.tactical.guardMaxAgentReadsPerTick,
    log: log.child({ component: "tactical-guard" }),
  });
  const runner = new JobRunner({
    pg,
    journal,
    connectorId: cfg.identity.connectorId,
    jobSigningPublicKey: cfg.identity.jobSigningPublicKey,
    deploySem,
    otherSem,
    log,
    deps: {
      tactical,
      index,
      downloader,
      cacheBaseUrl: cfg.cache.baseUrl,
      installScriptId: cfg.tactical.installScriptId,
      installScriptTimeoutSec: cfg.tactical.installScriptTimeoutSec,
      maxParallelCalls: cfg.tactical.maxParallelCalls,
      wu: {
        scanScriptId: cfg.tactical.wuScanScriptId,
        installScriptId: cfg.tactical.wuInstallScriptId,
        scanTimeoutSec: cfg.tactical.wuScanTimeoutSec,
        installTimeoutSec: cfg.tactical.wuInstallTimeoutSec,
      },
      log,
      trust: cfg.trust,
      guard,
      onAgentCount: (n) => {
        agentCount = n;
      },
    },
  });

  const cacheServer = new CacheServer({
    root: cacheDir,
    index,
    prefix: cachePathPrefix(cfg.cache.baseUrl),
    host: cfg.cache.listenHost,
    port: cfg.cache.port,
    tls: cfg.cache.tls ? { cert: await readFile(cfg.cache.tls.certFile), key: await readFile(cfg.cache.tls.keyFile) } : undefined,
    maxConcurrentDownloads: cfg.cache.maxConcurrentDownloads,
    perClientConcurrency: cfg.cache.perClientConcurrency,
    retryAfterSec: cfg.cache.retryAfterSec,
    bucket: cacheBucket,
    log: log.child({ component: "cache-server" }),
  });
  const addr = await cacheServer.start();
  log.info("package cache server listening", { host: cfg.cache.listenHost, port: addr.port, baseUrl: cfg.cache.baseUrl });

  let siem: SiemRelay | undefined;
  if (cfg.siem) {
    siem = new SiemRelay({
      pg,
      target: parseSiemUrl(cfg.siem.url),
      ca: await readOptional(cfg.siem.caFile),
      hostname: cfg.siem.hostname ?? hostname(),
      stateFile: join(cfg.stateDir, "siem-state.json"),
      pollIntervalMs: cfg.siem.pollIntervalSec * 1000,
      batchSize: cfg.siem.batchSize,
      log: log.child({ component: "siem-relay" }),
    });
    await siem.start();
  }

  // ---- Tactical status (cached; refreshed at most every statusIntervalSec) ----
  let tacticalStatus: Heartbeat["tactical"] = { reachable: false, agents: null, error: "not checked yet" };
  let tacticalCheckedAt = 0;
  const refreshTactical = async () => {
    if (Date.now() - tacticalCheckedAt < cfg.tactical.statusIntervalSec * 1000) return;
    tacticalCheckedAt = Date.now();
    try {
      const agents = await tactical.listAgents();
      agentCount = agents.length;
      tacticalStatus = { reachable: true, agents: agents.length, error: null };
    } catch (err) {
      tacticalStatus = { reachable: false, agents: agentCount, error: errorMessage(err).slice(0, 2000) };
    }
  };

  const applyLimits = (r: HeartbeatResponse) => {
    const installs = Math.max(1, Math.min(r.maxConcurrentInstalls, installCeiling));
    const bw = minNonNull(r.bandwidthLimitMbps, localBw);
    if (installs !== effective.maxConcurrentInstalls || bw !== effective.bandwidthLimitMbps) {
      log.info("limits updated from PatchGate", { maxConcurrentInstalls: installs, bandwidthLimitMbps: bw });
    }
    deploySem.setCapacity(installs);
    cacheBucket.setRate(bw ? mbpsToBytesPerSec(bw) : null);
    effective = { maxConcurrentInstalls: installs, bandwidthLimitMbps: bw };
    const skew = Date.parse(r.serverTime) - Date.now();
    if (Number.isFinite(skew) && Math.abs(skew) > 60_000) log.warn("clock skew with PatchGate exceeds 60 s; fix NTP (requests are rejected beyond 5 min)", { skewMs: skew });
  };

  const stopAll = new AbortController();
  const heartbeatNow = async (): Promise<HeartbeatResponse | null> => {
    await refreshTactical();
    await evictNow();
    const freeBytes = await volumeFreeBytes(cacheDir);
    const s = index.stats();
    const hb: Heartbeat = {
      version: opts.version,
      cacheBaseUrl: cfg.cache.baseUrl,
      cache: { files: s.files, bytes: s.bytes, freeBytes },
      tactical: tacticalStatus,
      siem: siem ? siem.status() : { configured: false, lastForwardedSeq: null, error: null },
      guard: guard.status(),
    };
    try {
      const r = await pg.heartbeat(hb, stopAll.signal);
      applyLimits(r);
      return r;
    } catch (err) {
      if (!stopAll.signal.aborted) log.warn("heartbeat failed", { error: errorMessage(err) });
      return null;
    }
  };

  const heartbeatLoop = (async () => {
    while (!stopAll.signal.aborted) {
      try {
        await sleep(cfg.limits.heartbeatIntervalSec * 1000, stopAll.signal);
      } catch {
        return;
      }
      await heartbeatNow();
    }
  })();

  const pollLoopFn = async (): Promise<void> => {
    let attempt = 0;
    while (!stopAll.signal.aborted && runner.accepting) {
      try {
        if (runner.load >= cfg.limits.maxQueuedJobs) {
          await sleep(1000, stopAll.signal);
          continue;
        }
        const jobs = await pg.getJobs(cfg.limits.pollWaitSec, stopAll.signal);
        attempt = 0;
        for (const j of jobs) await runner.submit(j);
      } catch (err) {
        if (stopAll.signal.aborted || err instanceof AbortedError) return;
        const retryAfter = err instanceof PatchGateError ? err.retryAfterMs : undefined;
        const delay = Math.max(retryAfter ?? 0, backoffDelay(attempt++, { baseMs: 1000, maxMs: 60_000 }));
        log.warn("job poll failed; backing off", { error: errorMessage(err), delayMs: delay });
        try {
          await sleep(delay, stopAll.signal);
        } catch {
          return;
        }
      }
    }
  };

  runner.resendUnposted();
  await heartbeatNow(); // apply PatchGate's limits before the first jobs arrive
  const pollLoop = pollLoopFn();
  guard.start(); // first round after one interval (the allow-set arrives with the first poll)
  log.info("connector running", { version: opts.version, siem: Boolean(siem), tacticalGuardSec: cfg.tactical.guardIntervalSec });

  let stopped: Promise<void> | undefined;
  return {
    runner,
    cacheServer,
    index,
    cachePort: addr.port,
    guard,
    limits: () => ({ ...effective }),
    heartbeatNow,
    stop: () => {
      stopped ??= (async () => {
        log.info("shutting down");
        stopAll.abort();
        await Promise.all([pollLoop, heartbeatLoop]);
        await guard.stop();
        await runner.shutdown(cfg.limits.shutdownGraceSec * 1000);
        await siem?.stop();
        await cacheServer.stop();
        await journal.close();
        log.info("stopped");
      })();
      return stopped;
    },
  };
}
