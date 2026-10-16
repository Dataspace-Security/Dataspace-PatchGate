# PatchGate (web)

Approval-gated patch management for **offline** bank PCs. PatchGate is the only component with
internet access; Tactical RMM (server + agents) is offline and only delivers what PatchGate approves.
Design: [`../docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md).

Stack: Next.js 16 (App Router) · TypeScript · PostgreSQL 16 · Prisma 6 · Vitest.

## Quick start (dev)

```bash
docker compose -f docker-compose.dev.yml up -d     # Postgres on 127.0.0.1:55432
cp .env.example .env                               # fill AUDIT_HMAC_KEY, WORKER_TOKEN (WSUS_TOKEN optional)
npm install
npm run db:migrate
npm run db:seed                                    # users, rings, window, 4 sample PCs, patches, 1 app
npm run dev                                        # http://localhost:3000 — switch user at /dev-login
```

Dev identity (cookie from `/dev-login`, else `DEV_USER_UPN`) works **only when `NODE_ENV=development`**.
Production requires SSO (not implemented yet) and refuses to start without `SIEM_SYSLOG_URL`.

## Panel

| Page | What |
|---|---|
| Dashboard | % fully patched PCs, critical gaps, approvals waiting, failed deployments, PCs without a ring, SIEM export status |
| Patches | Filter, select, create a change request (ring + maintenance window + ticket). Ineligible items show why. |
| Change requests | Maker submits → checker approves/rejects → queue deployment. Buttons follow the server's state machine. Per-PC deployment status + audit trail. |
| Endpoints | Sync agents from Tactical, request scans, assign PCs to rings, missing/critical counts |
| Apps & mirror | Third-party allow-list (admin), package status incl. quarantine, Tactical release mirror with admin approve/reject, fetch runs |
| Audit | Chain integrity, SIEM export lag, verify an anchor copied from the SIEM, latest events |

## Schedulers (production)

| Call | Every | Does |
|---|---|---|
| `POST /api/worker/tick` (`x-worker-token`) | 1 min | deploy queue (in window, 1 in-flight per PC, retries transient Tactical errors) → confirm installs → finalise CRs → scan ingestion → **audit export to SIEM** |
| `POST /api/worker/fetch` (`x-worker-token`) | 1 h | third-party apps (daily) + Tactical releases (daily). **Only path to the internet.** |
| `scripts/wsus/Export-WsusCatalog.ps1` | after WSUS sync | Windows catalog → PatchGate |
| `scripts/wsus/Sync-WsusApprovals.ps1` | ≤ 10 min | approves PatchGate-approved updates per ring group in WSUS |

## Audit trail → SIEM (mandatory)

Every audit event is HMAC-chained in Postgres (UPDATE/DELETE/TRUNCATE blocked by triggers) **and** streamed to the
bank SIEM as RFC 5424 syslog over TLS:

| msgId | Fields (structured data `patchgate@32473`) | When |
|---|---|---|
| `AUDIT` | `seq`, `hash`, `prevHash` + JSON body (actor, action, entity, payload) | every event, in order |
| `ANCHOR` | `seq`, `hash`, `count`, `mac` (HMAC with the audit key) | after each exported batch |
| `HEARTBEAT` | `seq`, `hash` = **real DB head**, `total`, `mac` | hourly, always |

**SIEM rules the bank must configure** (logic is unit-tested in `src/lib/siem/verify-stream.ts`):

| Rule | Detects | Alert when |
|---|---|---|
| Chain continuity | tail rows deleted after export, then new events written | an `AUDIT.prevHash` ≠ the previous `AUDIT.hash` |
| Regression | rows deleted, nothing new written | `HEARTBEAT.seq` or `ANCHOR.seq` < max exported `seq` |
| Fork | history rewritten | same `seq` seen with two different `hash` values |
| Silence | PatchGate stopped / export blocked | no `HEARTBEAT` from `patchgate` for > 2 h |

Splunk example (chain continuity):

```
index=security sourcetype=syslog appname=patchgate msgid=AUDIT
| rex "seq=\"(?<seq>\d+)\" hash=\"(?<hash>[a-f0-9]+)\" prevHash=\"(?<prev>[a-f0-9]+)\""
| sort 0 seq | streamstats current=f last(hash) as expected_prev
| where isnotnull(expected_prev) AND prev!=expected_prev
```

Inside PatchGate, `/audit` additionally re-verifies the whole chain against the exported anchors and lets an auditor
check any `ANCHOR` copied from the SIEM. A DB superuser can disable triggers and delete rows, but cannot hide that from
the SIEM copy, and cannot re-forge hashes without the HMAC key (kept outside the DB host).

## Third-party apps

winget metadata → exact-host allow-list per app → stream download (size-limited) → SHA-256 must equal manifest →
Authenticode signature valid **and** exact publisher pin (`O=<organisation>`) → published to repo → quarantined
`QUARANTINE_HOURS` → approvable. Install on PCs via the signed `scripts/endpoint/Install-PatchGatePackage.ps1`, which
re-verifies hash + signature.

**Installer selection:** a machine-scope **MSI** is always preferred. Otherwise an **EXE** is accepted only with a
known-safe silent switch set — command lines are never taken verbatim from the internet:

| winget technology | Switches used | Source |
|---|---|---|
| `msi` / `wix` | `msiexec /i … /qn /norestart` | fixed |
| `nullsoft` (NSIS) | `/S` | fixed |
| `inno` | `/SP- /VERYSILENT /SUPPRESSMSGBOXES /NORESTART` (+ `/ALLUSERS` for machine scope) | fixed |
| `burn` (WiX bundle) | `/quiet /norestart` | fixed |
| generic `exe` | manifest `Silent` switches **only if every token is allow-listed** (e.g. 7-Zip `/S`) | validated |

Value-carrying switches (`/D=…`, `/LOG=…`) are always rejected. The allow-list in
`src/lib/thirdparty/switches.ts` and the PC script are kept identical by a unit test.

> Rolling vendor URLs (e.g. Google Chrome enterprise MSI) change content without changing URL, so the winget hash goes
> stale and the fetcher **rejects** them by design. See ARCHITECTURE §11 R6.

## Tactical RMM configuration (required)

`local_settings.py`: `TRMM_DISABLE_APPROVE_UPDATES_TASK = True`, `TRMM_DISABLE_WINUPDATES_INSTALL_TASK = True`,
`TRMM_DISABLE_AGENT_AUTO_UPDATE_TASK = True`, `INSTALL_NUSHELL = False`, `INSTALL_DENO = False`.
Default patch policy: **every severity = `manual`** (PatchGate detects otherwise and refuses to install).
Agent/server updates come from the PatchGate mirror (`/repo/tactical/...`); public agent builds are unsigned, so an admin
approves each after the SHA-256 matched GitHub's published digest.

**Agent upgrades** go through the normal change-request flow:
1. An approved agent build creates a patch "Tactical RMM agent X.Y.Z" (kind `AGENT_UPGRADE`); newer builds supersede older ones.
2. Scan ingestion records each PC's agent version + architecture → compliance shows which PCs need it.
3. Maker selects it on **Patches → Tactical agent**, checker approves, deploy.
4. The worker pushes the build for the PC's architecture (`amd64` / `386`); PCs already at the target are skipped.
   It always runs **last** in a change request, because the agent restarts.
5. The install script verifies the pinned SHA-256 and hands the Inno installer (`/VERYSILENT`) to a one-time SYSTEM
   scheduled task (30 s), so the upgrade survives the agent restart.
6. Success is recorded only when Tactical reports the new agent version.

## Rate limiting

`src/proxy.ts` rate-limits every request per client address × route class (token bucket; `429` + `Retry-After`):

| Class | Routes | Limit (per minute / burst) |
|---|---|---|
| auth | `/api/dev-login` | 10 / 5 |
| audit | `/api/audit/*` | 20 / 10 |
| machine | `/api/worker/*`, `/api/wsus/*` (token brute force) | 120 / 30 |
| write | other `/api/*` POST/PATCH/PUT/DELETE | 60 / 20 |
| read | other `/api/*` GET | 300 / 100 |
| repo | `/repo/*` (branch PCs downloading packages) | 1200 / 300 |
| page | panel pages | 600 / 200 |

Behind the bank's reverse proxy set `TRUST_PROXY_HOPS=1` so limits are per client; without it `X-Forwarded-For` is
ignored (spoofable) and clients share one bucket per class. Limits are per process — for several PatchGate instances,
move the store to Redis/Postgres (policy unchanged).

## Tests

| Command | What |
|---|---|
| `npm test` | 141 unit tests (no DB, no network) |
| `TEST_DATABASE_URL=… npm run test:int` | 20 integration tests on a real `patchgate_test` DB (audit tamper detection, SIEM export, deploy flow, retries, WSUS, scan ingest) |
| `LIVE_FETCH=1 TEST_DATABASE_URL=… npm run test:int` | + live internet: real PowerShell MSI via winget, real Tactical release mirror |

## Not built yet

- SSO (SAML/LDAPS + MFA) — production returns 401 until then
- Rolling-URL vendors (Chrome): needs a signature-trust + MSI-version-read path instead of manifest hash
- Validate on real infrastructure: WSUS scripts (syntax-checked only), the install script's EXE + agent
  scheduled-task paths on a real bank PC image (input rejection is tested; actual installs are not)
- Shared rate-limit store for multi-instance deployments
