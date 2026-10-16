# PatchGate hosted lab

Mirrors the hosted, multi-bank architecture (docs/ARCHITECTURE-HOSTED.md): PatchGate runs on **our server**,
and each bank site has an offline Tactical RMM plus a **PatchGate Connector**. The connector only makes outbound
HTTPS calls to us. Tactical and the PCs never reach the internet, and the PCs never reach PatchGate.

```
 Internet ──► PatchGate = "our server" (this PC)  https://patchgate.patchgate-lab.internal:3443
                 ▲ local login (password only) · signed jobs · package downloads · audit feed
                 │ HTTPS, outbound only
 ┌─ BANK A (Docker, internal networks) ───────┼──────────────────────────────────────────────────────┐
 │  bank-a-firewall (socat): forwards ONLY :3443 PatchGate + :6514 bank SIEM to the lab host          │
 │  bank-a-connector (patchgate-connector:1.0.0, read-only, uid 1000)  10.231.50.40 / 10.231.51.20    │
 │     ├─► Tactical API https://api.<domain>:4443 (trmm-nginx, bank LAN = patchgate-lab-trmm_proxy)    │
 │     ├─► bank SIEM tls://siem.<domain>:6514 (lab: lab/siem/receiver.mjs on the host)                 │
 │     └─◄ package cache https://pg-cache.<domain>:8443/repo  ◄── trmm-lab-ingress :8443 ◄── bank PCs  │
 │  Tactical RMM 1.5.2 (11 containers, no outbound route) ◄── trmm-lab-ingress :443 ◄── bank PCs      │
 └────────────────────────────────────────────────────────────────────────────────────────────────────┘
   Windows Sandbox "Bank A PC": may reach ONLY api/rmm/mesh :443 + pg-cache :8443 (own firewall + hosts)
```

| What | Where |
|---|---|
| PatchGate (our server) | `https://patchgate.patchgate-lab.internal:3443` — `next dev` over HTTPS, `AUTH_MODE=local`, `JOB_SIGNING_KEY_FILE`, `PUBLIC_BASE_URL`. **No route to any Tactical**: `TACTICAL_API_URL` points at `*.invalid`. |
| Scheduler | `lab/patchgate/scheduler.sh`: worker tick every minute, internet fetch every hour. Log: `lab/patchgate/scheduler.log`. |
| Bank A Tactical | `https://rmm.patchgate-lab.internal` (login in `lab/tactical/.env`). Three fixed PatchGate scripts are registered (`provision.json`: install / WU scan / WU install ids). |
| Bank A connector | container `bank-a-connector`. Config: `lab/connector/bank-a/etc/connector.json`. Bank trust policy: `lab/connector/bank-a/trust-policy.json`. State lives in the docker volume `patchgate-lab-bank-a_bank-a-state`. |
| Bank A package cache | `https://pg-cache.patchgate-lab.internal:8443/repo/<repoPath>`. The certificate is issued by the lab CA (`lab/certs/out/ca.crt`). |
| Bank A SIEM | `lab/siem/received.log` (TLS syslog :6514). Check the relay with `node lab/siem/check.mjs bank-a-connector-hq`. |

**Credentials** (all gitignored): `lab/patchgate/lab-users.json` (local accounts: password, role, bank),
`lab/patchgate/secrets.env` + `lab/patchgate/secrets/job-signing-key.pem`, `lab/tactical/.env`,
`lab/tactical/provision.json`, `lab/connector/bank-a/etc/{tactical-api-key,cache-key.pem}`.

| Account | Role |
|---|---|
| `lab-admin@patchgate.lab` | platform ADMIN: banks, connectors, users, trust decisions, raises change requests (maker) |
| `lab-auditor@patchgate.lab` | platform AUDITOR: read-only across every bank |
| `admin@bank-a.lab` / `approver@bank-a.lab` | Bank A ADMIN ×2 (bank admins approve = checkers; two so maker ≠ checker works inside the bank) |
| `viewer@bank-a.lab` | Bank A AUDITOR (read-only; historic UPN) |

`lab-operator@patchgate.lab` (old platform operator) was mapped to AUDITOR by the role migration and is no longer used.

**Sign-in is password only** (local sign-in has no second step by design, as in production; banks needing MFA use
their SSO). Open the URL and enter the password from `lab-users.json` (`node lab/patchgate/show-login.mjs <upn>`
prints it). Scripts call the real API as a user with `node lab/patchgate/pg-api.mjs <upn> GET /api/...`.

## One-time setup (this PC)
1. Admin PowerShell: `powershell -ExecutionPolicy Bypass -File lab\host-setup.ps1`. It sets the hosts entries
   (incl. `pg-cache`), firewall rules for 3443 + 443/8443 from private ranges, and enables Windows Sandbox.
   **Restart the PC once.**
2. `bash lab/certs/make-certs.sh patchgate-lab.internal` (lab root CA + wildcard certificate).
3. Third-party apps and agent builds, if the DB is new: see "Catalog" below.

## Start / stop
```bash
bash lab/up-all.sh      # PKI → Tactical (isolation proof) → SIEM → PatchGate → users → connector (enrol + proofs) → scheduler
bash lab/down-all.sh    # stops everything; data kept (DB, Tactical volumes, connector state). --keep-tactical to leave Tactical up
```
Every step can also run on its own:

| Script | Does |
|---|---|
| `lab/tactical/up.sh` | Starts the real Tactical. **Fails if any container can reach the internet** (raw IP + DNS). |
| `lab/tactical/provision.sh` | Service account + API key, client/site, the 3 scripts, manual patch policy. **Rotates the API key**; `connector/up.sh` copies the new key. |
| `lab/patchgate/start.sh` | PatchGate (hosted). `LAB_MODE=dev` gives the old single-bank dev mode (`http://localhost:3000`, dev user switcher, direct Tactical link). `LAB_MODE=dev LAB_HTTPS=1` serves dev mode on :3443. Only one `next dev` per `patchgate-web`. |
| `lab/patchgate/users.sh` | Local accounts via `scripts/admin/create-user.ts`. Bank users are created once `bank-a` exists. |
| `lab/connector/enroll.sh [--force]` | Over the real admin API: bank `bank-a`, its app opt-ins, a one-time code, then `patchgate-connector init` with `--job-key-fingerprint` (the out-of-band pin). |
| `lab/connector/up.sh` | Image, bank CA/cert/key files, trust policy, config, start, and **proofs**: no internet (raw IP + DNS), PatchGate + Tactical reachable, Tactical cannot reach the bank firewall, cache `/healthz` reachable through the ingress. |
| `lab/connector/cache.sh <wingetId…> [agent:<ver>:<arch>] [--stage-agent <ver>]` | Lab trigger for signed `CACHE_PACKAGE` jobs (via PatchGate's own `ensurePackageCached`). In production, deployments and WU scans create these jobs themselves. |
| `lab/patchgate/stop.sh [scheduler\|siem]` | Stops the lab node processes (PowerShell; `next dev` children included). |

## Validate (no Sandbox needed)
```bash
C="--ssl-no-revoke --cacert lab/certs/out/ca.crt --resolve pg-cache.patchgate-lab.internal:8443:127.0.0.1"
curl $C -o putty.msi https://pg-cache.patchgate-lab.internal:8443/repo/pkgs/PuTTY.PuTTY/0.85.0.0/PuTTY.PuTTY-0.85.0.0.msi   # 200, sha256 = DB
curl $C --path-as-is https://pg-cache.patchgate-lab.internal:8443/repo/../../etc/passwd                                     # 404
node lab/siem/check.mjs bank-a-connector-hq
cd patchgate-web && npx playwright test -c playwright.lab.config.ts          # UI journey, screenshots in e2e-lab/screenshots
```

## Windows Sandbox "Bank A PC" (after the restart)
`bash lab/sandbox/make-sandbox.sh 2.10.0`, then double-click `lab/sandbox/generated/PatchGateLab.wsb`. The full
checklist is in **lab/sandbox/AFTER-RESTART.md**.

## Spare physical PC "Bank A PC" (when Sandbox / VirtualBox are not usable on this host)
`bash lab/pc-kit/build-kit.sh 2.10.0` builds `lab/pc-kit/generated/PatchGateBankPC/` (lab CA, lab.json with a
fresh 24 h install token, outdated apps, the same `bootstrap.ps1`). Copy it to a USB stick; on a spare
Windows 10/11 PC on this LAN run `Start-BankPC.ps1` as admin (backup first, then the bootstrap, results copied
back to the kit's `out\`). `Undo-BankPC.ps1` (`-WhatIf` for a dry run) restores the PC. Operator checklist:
**lab/pc-kit/RUN-ON-SPARE-PC.md**; user instructions: `README.txt` in the kit. `make-sandbox.sh` and
`build-kit.sh` share `lab/pc-kit/bank-pc-common.sh` (cache check, install token, lab.json).

## Catalog (only for a new DB)
```bash
cd patchgate-web && GITHUB_TOKEN=$(gh auth token) npx tsx scripts/lab/discover-apps.ts   # signer orgs, hosts, old + new
# allow-list lab/apps/allowlist.json → POST /api/apps (admin) → POST /api/worker/fetch
bash lab/fixtures/stage-old-agent.sh 2.10.0                       # older agent (GitHub digest verified)
bash lab/connector/cache.sh --stage-agent 2.10.0 agent:2.10.0:amd64  # register it + put it in the Bank A cache
node lab/sandbox/stage-fixtures.mjs                               # outdated apps the Sandbox PC starts with
```

## Verified 2026-10-15 (hosted lab)
| Check | Result |
|---|---|
| Tactical containers: raw IP + DNS egress | all 11 **blocked** |
| Connector egress | 1.1.1.1:443, 140.82.112.3:443, 8.8.8.8:53, DNS, and firewall :22 all **blocked**. PatchGate /api/health 200. Tactical API reachable (401 without key). Tactical → bank firewall **blocked**. |
| Enrolment | real admin API + one-time code; `init` pins the job key by fingerprint. Wrong fingerprint is refused and nothing is saved. |
| Jobs | `SYNC_AGENTS` against the real Tactical (0 agents) SUCCEEDED. `CACHE_PACKAGE` for wsusscn2.cab (683 MB), agent 2.10.0/2.11.0 and 8 apps SUCCEEDED. Ticks `ok:true`. |
| Cache | downloads hash-identical. Unknown, uncached, traversal and dot-file paths → 404. POST → 405. No lab CA → TLS refused. Per-client limit 2 → 3rd download 503 + `Retry-After: 30`. PatchGate-set 20 Mbit/s → measured 20.1 Mbit/s. |
| Bank trust policy | app not listed → `CACHE_PACKAGE` refused before download. Publisher pin lists with commas (Zoom, Temurin) accepted. |
| SIEM relay | Bank A chain arrives as `bank-a-connector-hq`: no fork, no regression. Relay records carry **no prevHash**, so chain linkage cannot be verified. |
| UI (Playwright, 7 tests) | password-only sign-in, wrong password refused, bank + enrolment code created in the UI, connector online, bank switch, endpoints/discovery, bank user isolation |

## Known lab findings
- **Temurin** renamed its signing organisation between versions, so pin lists (`O=A; O=B`) are supported.
  **Notepad++** ids contain `+`. **VLC** redirects to random mirror hosts, which the host allow-list rejects.
- Windows `curl` (Schannel) needs `--ssl-no-revoke` with the CRL-less lab CA.
- `next dev --experimental-https` **replaces** `NODE_EXTRA_CA_CERTS` with `--experimental-https-ca` (start.sh passes it).
- `next dev` blocks its HMR socket for non-localhost origins, and the page then never hydrates. `next.config.ts` has
  `allowedDevOrigins: ["patchgate.patchgate-lab.internal"]` for this.
- **Bank rings are a lab fixture**: onboarding a bank creates no rollout rings, and nothing in the app can create
  them, but a change request needs one. `connector/enroll.sh` inserts Ring0-Test, Ring1-Pilot and Ring2-Prod for Bank A.
- Every PC reaches the cache through the socat ingress, so the connector sees **one** client IP. In the lab,
  `perClientConcurrency` therefore applies to all PCs together.
- Git Bash: `docker` arguments with container paths need `MSYS_NO_PATHCONV=1` (any value disables conversion).
  Mingw `openssl` needs the conversion, so do not export it globally.
