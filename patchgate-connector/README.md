# PatchGate Connector

Small service that runs **next to a bank site's Tactical RMM server**. It is the only component in the
bank that talks to PatchGate, and it only makes **outbound HTTPS** calls. Nothing connects into the bank.

```
PatchGate (our DC) ◄── HTTPS, outbound only, signed requests ── Connector ──► Tactical RMM API (local)
                                                                   │
                                     PCs ── HTTPS (bank LAN) ──►  package cache (:8443)
                                                                   └──► bank SIEM (syslog over TLS)
```

What it does:
- **Jobs.** Long-polls PatchGate for **signed, typed jobs**. Checks each job's signature against the pinned
  job-signing key, the connector id, the validity window and the typed payload. Then runs it against the
  local Tactical API and posts the result. It never makes an arbitrary Tactical call.
- **Package cache.** Downloads each approved package once (`CACHE_PACKAGE`), checks its SHA-256 and
  serves it to the PCs on the bank LAN, with limits that protect the network.
- **Audit relay.** Forwards the bank's audit chain to the bank SIEM as RFC 5424 records over TLS.
- **Heartbeat** every 60 s. It reports cache and Tactical health, and receives `maxConcurrentInstalls` and
  `bandwidthLimitMbps` from PatchGate.

The protocol contract is `src/protocol.ts`. It is a byte-identical copy of
`patchgate-web/src/lib/connector/protocol.ts`, and `npm test` fails if the two copies differ.

## Install

The connector is one file, `dist/patchgate-connector.mjs` (Node 24, no `node_modules` at runtime).

```bash
npm ci && npm test && npm run build          # → dist/patchgate-connector.mjs
```

- **systemd:** see `deploy/patchgate-connector.service` (hardened unit, dedicated user, only
  `/var/lib/patchgate-connector` writable).
- **Docker:** `docker build -t patchgate-connector:1.0.0 .`, then see `docker-compose.example.yml`. The image
  is non-root (uid 1000) with a read-only root filesystem. Only `/var/lib/patchgate-connector` is writable,
  plus a small `/tmp` tmpfs.

Before enrolling:
1. Copy `config.example.json` to `/etc/patchgate-connector/connector.json` and fill in the Tactical and
   cache sections.
2. Put the Tactical API key in `tactical.apiKeyFile` (mode 0640). You can use env
   `PATCHGATE_TACTICAL_API_KEY` instead.
3. Issue the cache TLS certificate from the **bank's internal PKI**, for the host name used in
   `cache.baseUrl`.
4. In Tactical: upload the signed `Install-PatchGatePackage.ps1` script and put its id in
   `tactical.installScriptId`. Set **every patch-policy severity to `manual`**. Tactical's install endpoint
   re-approves updates by policy, and the connector refuses to install if the approval state does not match
   the job exactly.

## Enrol

A PatchGate platform admin creates a one-time enrolment code for the bank. Codes are valid for 24 h and
work once.

```bash
PATCHGATE_ENROLL_CODE=7Q2M-K9XD-4HPA-ZT3W-8NBC \
  node patchgate-connector.mjs init --config /etc/patchgate-connector/connector.json \
       --server https://patchgate.example.com --ca /etc/patchgate-connector/patchgate-ca.pem \
       --job-key-fingerprint <64 hex digits from the PatchGate operator>
```

**Job-signing key fingerprint (required).** The connector pins PatchGate's job-signing key at enrolment.
To make sure it pins the *real* key (and not one injected by an intercepting proxy or a spoofed server),
`init` refuses to run without `--job-key-fingerprint` (or env `PATCHGATE_JOB_KEY_FINGERPRINT`), unless
`--insecure-dev` is given (labs only). Get the fingerprint from the PatchGate operator **out of band**
(phone, signed letter: a channel other than the one that carried the enrolment code). Format: the lowercase
hex **SHA-256 of the raw 32-byte Ed25519 public key** (not of its base64 text), e.g.
`9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08`. Upper case, `:` separators and a
`sha256:` prefix are accepted. The operator computes it from the base64 key with:

```bash
echo -n '<jobSigningPublicKey base64>' | base64 -d | sha256sum
```

On a mismatch nothing is saved (no key, no identity) and the error names both fingerprints. The code is
spent: ask for a new one after clarifying with the operator.

`init` does the following:
- Generates an Ed25519 key locally and writes it to `<stateDir>/connector-key.pem` (mode 0600). The key
  never leaves the bank.
- Proves possession of the key and enrols with the code.
- Checks the fingerprint of PatchGate's `jobSigningPublicKey` against `--job-key-fingerprint`, then pins it.
- Writes `server` and `identity` into the config.

`--ca` pins our CA: only that CA is trusted, instead of the system roots. `http://` servers are refused
unless you pass `--insecure-dev` (labs only). `--force` re-enrols with a new key. The old key is kept until
the new enrolment succeeds.

```bash
node patchgate-connector.mjs check --config …   # JSON line per probe; exit 0 healthy, 1 unhealthy
node patchgate-connector.mjs run   --config …   # the service; SIGTERM / SIGINT = graceful shutdown
```

**Windows hosts.** The connector can also run as a Windows service through a wrapper (WinSW, NSSM, PM2).
Graceful shutdown is triggered by Ctrl+C (SIGINT), Ctrl+Break (SIGBREAK, what WinSW/NSSM send on service
stop), console close (SIGHUP) and the IPC message `shutdown` (PM2 on Windows). Set the wrapper's stop
timeout above `limits.shutdownGraceSec`. Renames and deletes in the state and cache directories are retried
with backoff on EPERM/EBUSY/EACCES (anti-virus, indexer), and a cached file is never deleted while a PC is
downloading it.

Exit codes: 0 ok, 1 unhealthy (check), 2 usage, 3 config error, 4 runtime error.

## Configuration reference (`connector.json`, validated by zod; unknown keys rejected)

Relative paths are resolved against the config file's directory.

| Key | Default | Meaning |
|---|---|---|
| `stateDir` | — | Key, journal, cache index, SIEM position. The default cache lives under `stateDir/cache`. |
| `logLevel` | `info` | `debug` / `info` / `warn` / `error`. JSON lines go to stdout. Secrets are redacted. |
| `insecureDev` | `false` | Allows http/tcp URLs and a plain-HTTP cache. **Never use it in a bank.** |
| `server.url` / `server.caFile` | set by `init` | PatchGate origin and pinned CA. |
| `server.requestTimeoutMs` | 30000 | Per-request timeout. The long poll adds the wait time. |
| `server.downloadLimitMbps` | null | Optional cap on package downloads from PatchGate (internet uplink). |
| `identity.*` | set by `init` | `connectorId`, `tenantId`, `name`, pinned `jobSigningPublicKey`, `privateKeyFile`. |
| `tactical.url` | — | Tactical API base URL (https). |
| `tactical.apiKeyFile` | — | File holding the API key. Env `PATCHGATE_TACTICAL_API_KEY` is the alternative. |
| `tactical.caFile` | — | Bank CA for Tactical's certificate. |
| `tactical.installScriptId` | — | Fixed id of the signed install script. Without it, `DEPLOY_PACKAGE` fails. |
| `tactical.installScriptTimeoutSec` | 900 | Script timeout. |
| `tactical.wuScanScriptId` | — | Fixed id of the signed `Invoke-PatchGateWuScan.ps1`. Without it, `WU_SCAN` fails. |
| `tactical.wuInstallScriptId` | — | Fixed id of the signed `Install-PatchGateWinUpdate.ps1`. Without it, `WU_INSTALL` fails. |
| `tactical.wuScanTimeoutSec` | 3600 | Offline scan timeout (300..7200). The first scan on a PC also copies ~700 MB from the cache. |
| `tactical.wuInstallTimeoutSec` | 3600 | Timeout of one Windows-update install run (300..7200). |
| `tactical.timeoutMs` | 30000 | Timeout for Tactical calls. |
| `tactical.statusIntervalSec` | 300 | How often the heartbeat refreshes Tactical reachability and the agent count. |
| `tactical.maxParallelCalls` | 8 | Parallel Tactical calls inside one SCAN or COLLECT batch. |
| `tactical.guardIntervalSec` | 30 | Real-time Tactical guard round (protocol §8): reads Tactical's audit log + update approvals, resets approvals PatchGate did not authorise, pushes both to PatchGate. `0` = off (PatchGate's TACTICAL_AUDIT_SYNC / COLLECT backstop only). |
| `tactical.guardMaxAgentReadsPerTick` | 25 | Cap on `GET /winupdate/<agent>/` reads per guard round (only PCs Tactical flags with pending approvals are read; + one verification read per PC where something was reset). |
| `cache.baseUrl` | — | URL the PCs use. Passed to the script as `PG_REPO_URL`. Its path (e.g. `/repo`) is the served prefix. Must match `https://host[:port][/path]`. |
| `cache.listenHost` / `cache.port` | `0.0.0.0` / 8443 | Cache listener. |
| `cache.tls.certFile` / `keyFile` | — | Required. Certificate from the bank's internal PKI. |
| `cache.dir` | `stateDir/cache` | Package files: `<dir>/<repoPath>`. Downloads in progress go to `<dir>/.tmp`. |
| `cache.maxPackageBytes` | 4 GiB | Size cap per package. |
| `cache.minFreeBytes` | 1 GiB | Free-space floor of the cache volume. Before a download, unused packages are evicted (see `maxCacheBytes`). If the floor still cannot be kept, `CACHE_PACKAGE` fails **permanently** ("cache disk below its floor"). Free space is reported in every heartbeat (`cache.freeBytes`). |
| `cache.maxCacheBytes` | null | Optional size cap of the cache. Least-recently-used packages that **no unexpired job refers to** and that no PC is downloading are evicted (at start, every heartbeat, before each download). A package a job needs is pinned until that job's `expiresAt`. If the cap cannot be kept, `CACHE_PACKAGE` fails permanently ("cache full"). Partial downloads left by a crash (`<dir>/.tmp`) are removed at start. |
| `cache.maxConcurrentDownloads` | 50 | Global cap on concurrent downloads. Excess requests get 503 + Retry-After. |
| `cache.perClientConcurrency` | 2 | Cap per client IP. |
| `cache.bandwidthLimitMbps` | null | **Bank ceiling** for all downloads together (one shared token bucket). PatchGate's heartbeat value can only lower it. |
| `cache.retryAfterSec` | 30 | Retry-After value on 503. |
| `limits.maxConcurrentInstalls` | 50 | Local ceiling for concurrent `DEPLOY_*` jobs. The effective value is min(heartbeat, this, `maxConcurrentDownloads`). Before the first heartbeat it is 5. |
| `limits.maxConcurrentOtherJobs` | 4 | SYNC, SCAN, COLLECT, RESET and CACHE jobs. |
| `limits.maxQueuedJobs` | 200 | Polling pauses while this many jobs are queued or running. |
| `limits.heartbeatIntervalSec` / `pollWaitSec` | 60 / 25 | Heartbeat interval and long-poll wait. |
| `limits.shutdownGraceSec` | 60 | How long running jobs may finish after SIGTERM. |
| `limits.journalRetentionDays` | 30 | Upper bound for keeping the dedupe stub of an acknowledged job. Stubs are dropped earlier, once the job's signed `expiresAt` (max 72 h) has passed. |
| `limits.journalMaxBytes` | 64 MiB | Size cap of `journal.jsonl` (min 1 MiB). Compacted at runtime; beyond the cap the oldest acknowledged stubs are evicted. Undelivered results are never dropped. |
| `trust.publishers` | — | Optional **bank-held** publisher pins: `{ "<wingetId>": ["O=<publisher>", …] }`. See "Local trust policy". |
| `trust.allowUnlistedApps` | false | With `trust.publishers` set: also allow msi/exe apps that are not listed. |
| `trust.agentSha256` | — | Optional allow-list of Tactical agent build SHA-256s (lowercase hex). Any other agent build is refused. |
| `siem.url` / `caFile` | — | `tls://host:port` and the bank CA. Optional; leave it out to disable the relay. |
| `siem.hostname`, `pollIntervalSec`, `batchSize` | os hostname, 30, 500 | Relay settings. |

## Local trust policy (optional)

Defence in depth against a **compromised PatchGate platform**. PatchGate signs every job, but the bank can
decide locally which publishers may ever be installed through this connector. The policy lives in the
bank-controlled config file; PatchGate cannot change it. Example bank policy:

```json
"trust": {
  "publishers": {
    "7zip.7zip": ["O=Igor Pavlov"],
    "Mozilla.Firefox": ["O=Mozilla Corporation"],
    "Notepad++.Notepad++": ["O=Notepad++"]
  },
  "allowUnlistedApps": false,
  "agentSha256": ["<sha256 of tacticalagent-v2.10.0-windows-amd64.exe, lowercase hex>"]
}
```

- **`trust.publishers`** (msi/exe, in `CACHE_PACKAGE` and `DEPLOY_PACKAGE`): the job's `wingetId` must be
  listed, and every `O=…` in the job's `publisher` must be one of the local pins (exact, case-sensitive).
  The job may only **narrow** the list (send a subset), never add or replace a publisher. The PC-side script
  then checks the Authenticode signer against the job's (already narrowed) pin. Unlisted apps are refused
  unless `allowUnlistedApps` is true. A refused `CACHE_PACKAGE` downloads nothing.
- **`trust.agentSha256`** (kind `agent`: Tactical agent builds, which are unsigned): only these hashes are
  cached or installed.
- **Microsoft updates** (`msu` / `cab` / `wsusscan`): nothing to configure ("Microsoft only" is always
  enforced). The PC-side scripts require a valid Microsoft Authenticode signature regardless of the job.
- Without a `trust` section the signed job is the only authority (previous behaviour). Refusals are
  permanent job failures, logged with `security: true`, the package, its hash and the reason.

## Firewall rules

| Direction | From → To | Port | Why |
|---|---|---|---|
| Outbound | connector → PatchGate (our IP / domain only) | 443/tcp | Jobs, results, packages, heartbeat, audit. This is the connector's **only** internet egress. Works through a proxy; requests and jobs are signed end to end. |
| Outbound (LAN) | connector → Tactical API | 443/tcp | Local Tactical REST API. |
| Outbound (LAN) | connector → bank SIEM | e.g. 6514/tcp | Syslog over TLS (optional). |
| Inbound (LAN) | PC / branch subnets → connector | `cache.port` (8443/tcp) | Package downloads by the install script. |
| Inbound | anything else | — | **Deny.** Nothing from the internet connects to the connector. |

Tactical and the PCs keep **no** internet access.

## Sizing

- **CPU / RAM:** 1–2 vCPU and 256–512 MB are enough for a 5,000-agent site. Most of the work is I/O.
  SHA-256 re-checks of large packages are coalesced and memoised.
- **Disk:** the packages in use plus `minFreeBytes`. Typically 20–50 GB. Use fast local disk; NFS is not
  needed.
- **Bandwidth:** set `cache.bandwidthLimitMbps` to what the bank allows on the LAN/WAN, e.g. 200–500 Mbit/s
  at a data centre and lower for branch-heavy sites. 50 concurrent installs × ~200 MB packages at
  200 Mbit/s takes about 7 minutes per wave.
- One connector per Tactical server. For HA, add an optional standby; PatchGate leases jobs, and jobs are
  idempotent.

## State files (`stateDir`)

| File | Content |
|---|---|
| `connector-key.pem` | Ed25519 private key (0600). Back it up, or re-enrol if it is lost. |
| `journal.jsonl` | Append-only, fsync'd job journal: `start` / `done` / `posted`. Full result bodies are kept only until PatchGate acknowledges them; read-only results (`SYNC_AGENTS`, `SCAN`, `COLLECT`, `WU_SCAN`) are never written with their body. Afterwards a small stub stays (id, type, ok/retryable/outcomeUnknown, times, job expiry) until the job expires. Compacted at start and at runtime; capped by `limits.journalMaxBytes`. |
| `cache-index.json` | Verified cache index: the **only** files the cache server serves. Also holds the eviction pins (`repoPath` → expiry of the latest job that needs it). |
| `siem-state.json` | `lastForwardedSeq`, written only after a batch was flushed to the SIEM socket. |

## Windows updates without WSUS (WU_SCAN / WU_INSTALL)

PCs never talk to the internet and there is no WSUS. PatchGate downloads Microsoft's signed offline scan
catalog (`wsusscn2.cab`, kind `wsusscan`) and, later, only the update files PCs actually need (kinds `msu` /
`cab`), each verified by digest + Microsoft Authenticode and quarantined like third-party packages. This
connector caches them under `winupdate/` like any other package (`CACHE_PACKAGE`) and runs two fixed,
bank-signed scripts through Tactical (register both in Tactical as PowerShell scripts, put their ids in
`tactical.wuScanScriptId` / `tactical.wuInstallScriptId`; sources in `patchgate-web/scripts/endpoint/`):

- **`WU_SCAN`** → `Invoke-PatchGateWuScan.ps1` on each agent (read-only, runs as SYSTEM). The PC copies the
  cab from this cache (`PG_REPO_URL` + `PG_PATH`, SHA-256 `PG_SHA256`), keeps one verified copy in
  `%ProgramData%\PatchGate\wsusscan`, checks the Microsoft signature, registers it as a temporary offline
  scan service (`AddScanPackageService`), searches `IsInstalled=0 and IsHidden=0` and unregisters the
  service again. It prints `PATCHGATE_RESULT=<json>` with the applicable updates and their Microsoft URLs;
  the connector validates that output strictly (it comes from a PC) and returns it per agent. Requires the
  Windows Update service (`wuauserv`) not to be disabled.
- **`WU_INSTALL`** → `Install-PatchGateWinUpdate.ps1` on one agent. Every file must be in this site's
  verified cache (re-hashed here first). Files go to the script as `PG_UPDATES`
  (`<updateId>,<KB|->,<msu|cab>,<sha256>,<size>,<repoPath>` joined by `;`, install order preserved); large
  jobs are split into several runs of at most 6000 characters, never splitting an update. The PC re-checks
  SHA-256 + Microsoft signature, installs with `wusa /quiet /norestart` (.msu) or
  `DISM /Online /Add-Package` (.cab) and skips KBs that are already installed (safe to re-run).
  `rebootPolicy` is passed only to the last run (`PG_REBOOT`); earlier runs never restart the PC.
  Results: `INSTALLED` / `PARTIAL` (per-update errors) / `NOTHING_TO_DO`, plus `rebootRequired`.
  `WU_INSTALL` counts against `maxConcurrentInstalls` like the other deploy jobs.

## Behaviour notes

- **Rejected jobs.** These are dropped with a security log line and get **no result**: a bad signature, an
  unsupported version, a job for another connector, a malformed envelope. A job whose `notBefore` is in the
  future is ignored until it is delivered again. Authentic jobs that are expired, valid for longer than
  72 h ("job lifetime too long"), have an invalid payload or an unknown type are answered with
  `{ok:false, retryable:false, error:"rejected by connector: …"}`.
- **Late start.** Jobs can wait for a free install slot. The validity window is checked again right before
  execution: a job whose `expiresAt` passed meanwhile is never started and is answered
  `{ok:false, retryable:false, error:"expired before start: …"}`.
- **Outcome unknown (installs).** If an install may have run but its result is not known, the connector
  answers `{ok:false, retryable:false, outcomeUnknown:true}` and **never** runs that install again;
  PatchGate confirms via inventory (`COLLECT` / `WU_SCAN`) instead of failing or re-queueing. This covers
  `DEPLOY_PACKAGE` and `WU_INSTALL` when Tactical's `runscript` gets no answer (connection lost, client
  timeout), a proxy gateway error or timeout (**408/502/503/504**: the proxy gives up while the script still
  runs), Tactical's `timeout` answer or output without a result line, and an install that was running
  when the connector stopped ("interrupted").
- **Idempotency.** Non-read-only jobs (`DEPLOY_*`, `WU_INSTALL`, `RESET_APPROVALS`, `CACHE_PACKAGE`) are
  never executed twice: while the result is unacknowledged the stored result is re-sent; afterwards (body
  dropped, stub kept) a re-delivery is answered "already executed … not executed again" (PatchGate's
  first-result-wins rule answers 409). Read-only jobs (`SYNC_AGENTS`, `SCAN`, `COLLECT`, `WU_SCAN`) that
  are delivered again are simply run again.
- **Retryable failures:** Tactical unreachable, timeouts, 5xx/429 (except on install script runs, see
  "Outcome unknown"), agent offline (Tactical 400 "Unable to contact the agent"), the package not cached
  yet, and install-script failures caused by the cache being busy (503 / timeouts). Everything else is
  permanent, including a cache disk below its floor or over `maxCacheBytes`.
- **Result size.** A `COLLECT` result never exceeds 24 MiB: the software lists (then update lists) of the
  largest agents are dropped and those agents get `error: "… omitted: …result limit…"`, so PatchGate can
  re-collect them in smaller batches. Any other result above the limit becomes a permanent failure.
- **`SYNC_AGENTS` above 10,000 agents** fails permanently instead of sending a truncated list (PatchGate
  would unassign the missing agents). Split the Tactical server into more sites.
- **Local trust policy refusals** are permanent failures ("refused by the bank's local trust policy: …"),
  logged with `security: true`.
- **`DEPLOY_WINDOWS` steps:**
  1. Reset stale approvals.
  2. Approve exactly the job's GUIDs.
  3. Read the state back and verify it.
  4. Install.

  On a mismatch it withdraws every pending approval and fails. GUIDs that are not offered on the agent
  are left out of `approved`.

## Server-side expectations (PatchGate must implement)

All paths are under `/api/connector/v1`. Signed headers and the canonical request are as in `protocol.ts`.
The signature covers `req.url` exactly as sent: path plus query, no normalisation.

| Endpoint | Expected behaviour |
|---|---|
| `POST /enroll` | Unsigned. Body `{code, publicKey, version, proof}`. The connector does not send `name`. Answer **200 or 201** with `{connectorId, tenantId, name, jobSigningPublicKey}`. Bad or used code: 403. `connectorId` and `tenantId` must match `^[A-Za-z0-9_-]{1,64}$`. |
| `GET /jobs?wait=N` | N ≤ 25. Hold the request up to N s. Return **200 `{jobs: [...]}`** (≤ 20); 204 is also treated as "no jobs". Job `id` must match `^[A-Za-z0-9_-]{1,64}$`. Sign the envelope with `signJob` and add **no extra fields**: unknown fields are part of the signed canonical JSON. Jobs stay leased until a result arrives; re-delivery is safe. |
| `POST /jobs/{id}/result` | **2xx** = accepted. **409** = a result already exists (first wins); the connector treats this as delivered. **404/410** = unknown job; the connector stops retrying. **400/422** = invalid; the connector stops retrying and logs. **413** = too large: the connector posts a small permanent failure (`"result too large …"`) instead and logs. Other non-retryable statuses (e.g. 401/403) stop the retry loop; the result stays journaled (non-read-only jobs) and is re-sent at the next start. 5xx/429/408/425 (honours `Retry-After`) and network errors are retried with backoff and jitter (1 s up to 5 min), and survive restarts. Failed results may carry `outcomeUnknown: true` (see Behaviour notes). |
| `POST /heartbeat` | **200** `{serverTime, maxConcurrentInstalls, bandwidthLimitMbps}`. The connector sends `siem: {configured:false, lastForwardedSeq:null, error:null}` when no SIEM is configured. |
| `GET /packages/{sha256}` | **Signed like every other call** (GET, empty-body hash). 200 with the raw bytes. `Content-Length` must equal the job's `size` if present. 404 = permanent failure. The connector re-hashes the bytes. |
| `GET /audit?after={seq}&limit=500` | 200 `{records, head}`, oldest first. `seq` values are decimal strings. The connector **rejects the whole page** (forwards nothing, keeps its position, logs with `security: true`) if a seq is not above `after` or not strictly increasing, if there are more than `limit` records, if a record lies beyond `head`, or if the page is short (fewer than `limit`) while `head` is further on (records withheld). Gaps between seqs are fine (seq is a platform-wide counter). |
| Errors | 401/403 on auth failure. Watch for clock skew: the connector warns above 60 s. |

`POST /inventory` (listed in the architecture document) is **not used**. Inventory travels in the
`SYNC_AGENTS` / `COLLECT` results, because `protocol.ts` defines no inventory schema.

## Development

```bash
npm test          # protocol sync check + vitest (unit + end-to-end against in-process fakes)
npm run typecheck
npm run build
```

`test/helpers/fake-patchgate.ts` is a complete fake of the server side of the protocol: enrolment,
signature, timestamp and nonce verification, signed jobs, results, packages, audit and heartbeat. It can
serve as a reference for the PatchGate implementation. The TLS fixtures in `test/fixtures` are a test-only
CA and a localhost certificate.

## Known gaps

- `DEPLOY_WINDOWS.rebootPolicy` is validated but not applied. Tactical's install API has no reboot
  parameter, so reboots follow the Tactical patch policy.
- Plain syslog has no application-level acknowledgement. Delivery is at-least-once up to "flushed to the
  socket", and the SIEM must de-duplicate on `seq` + `hash`.
- Standby connector / job leases are a server-side feature. The connector's journal is local to one host.
- Cache eviction only removes packages that no unexpired job refers to. A package evicted after its jobs
  expired is downloaded again by the next `CACHE_PACKAGE` (`DEPLOY_PACKAGE` reports "not in this site's
  cache" as retryable).
- The audit relay does not verify the hash chain itself. It checks order and completeness against `head`
  and forwards each record's `prevHash` in the structured data (like PatchGate's own exporter), so the
  SIEM's chain-break / fork / regression rules verify the chain.
