# After the PC restart: Bank A PC (Windows Sandbox) end to end

Windows Sandbox only works after the one-time restart (`lab\host-setup.ps1` enabled it). Run every command
from the repo root (`D:\Projects\Dataspace_Security\Dataspace-PatchGate`) in Git Bash.

## 1. Bring the lab back (≈ 5 min)
```bash
# Admin PowerShell, once after the restart: hosts gets pg-cache, firewall gets 443/8443 for the Sandbox.
#   powershell -ExecutionPolicy Bypass -File lab\host-setup.ps1
bash lab/up-all.sh                      # Tactical, SIEM, PatchGate https :3443, connector, scheduler, with isolation proofs
bash lab/sandbox/make-sandbox.sh 2.10.0 # NEW 24 h Tactical install token; checks the agent is in the Bank A cache
```
`up-all.sh` must end with `Bank A connector up and isolated.`, and every isolation line must say `blocked`.
If `make-sandbox.sh` reports that the agent is missing from the cache, run
`bash lab/connector/cache.sh --stage-agent 2.10.0 agent:2.10.0:amd64`, wait 1 minute and run it again.

## 2. Start the Bank A PC
**No working Sandbox on this host?** Use a spare physical PC on the LAN instead: `bash lab/pc-kit/build-kit.sh 2.10.0`,
copy `lab/pc-kit/generated/PatchGateBankPC` to a USB stick and follow **lab/pc-kit/RUN-ON-SPARE-PC.md**. The
results (`PatchGateBankPC/out/results.tsv`) have the same PASS lines as below; §3–§6 apply unchanged
(stop = `Undo-BankPC.ps1` on the PC instead of closing the Sandbox window).

Double-click `lab\sandbox\generated\PatchGateLab.wsb`. The bootstrap runs on its own (≈ 5–10 min, fixtures
included). The Sandbox window stays open; wait until `lab/sandbox/generated/out/DONE` exists, then check:
```bash
column -t -s $'\t' lab/sandbox/generated/out/results.tsv     # every line PASS
```
| Expected PASS line | Proves |
|---|---|
| `internet-blocked:github.com / www.microsoft.com / 8.8.8.8` | the PC has no internet |
| `patchgate-blocked:192.168.1.33:3443` and both `patchgate-blocked:https://…:3443/api/health` | **the PC cannot reach PatchGate** (by IP or by name) |
| `site-reachable:https://api…/core/version/` and `…pg-cache…:8443/healthz` | it reaches only its site Tactical + connector cache |
| `fixture:<app>` ×10 | outdated apps installed (Firefox 156, PuTTY 0.82, Git 2.55.0.2, Zoom 7.1, …) |
| `agent-sha256`, `agent-inno-install`, `agent-enroll`, `agent-service` | Tactical agent 2.10.0 **from the connector cache**, hash verified, enrolled, running |

On failure, read `lab/sandbox/generated/out/bootstrap.log`. Also check `docker logs bank-a-connector | grep cache`:
it should list one `GET /repo/tactical/agent/2.10.0/…` download.

## 3. Sync → inventory → discovery (PatchGate UI)
Open `https://patchgate.patchgate-lab.internal:3443`. Sign in as `lab-admin@patchgate.lab` (password in
`lab/patchgate/lab-users.json`; `node lab/patchgate/show-login.mjs lab-admin@patchgate.lab` prints it).
Choose **Acting for bank → Bank A**.
```bash
bash lab/connector/cache.sh --sync      # optional: SYNC_AGENTS now instead of on the hourly schedule
```
1. **Connectors**: Bank A HQ shows *online*, Tactical shows *Reachable · 1 agent*, and PCs = 1.
2. **Endpoints**: the Sandbox PC appears (random hostname). Set its ring to
   **Ring0-Test**; Bank A's rings are a lab fixture (see findings).
3. The next ticks run `SCAN` and then `COLLECT` (updates + software + agent version) for the new PC.
   **Discovery** then lists the installed software: the outdated fixtures are *managed* (Bank A opted in), and the
   rest (e.g. VLC, 7-Zip) are *unmanaged*.
4. **Patches**: third-party updates for the fixtures (Firefox 157.0.1, PuTTY 0.85, …) and the agent upgrade
   2.10.0 → 2.11.0. Tactical holds every Windows approval: the patch policy is all-`manual`, and connector
   `RESET_APPROVALS` withdraws stale ones.

## 4. Maker / checker / deploy (third-party + agent upgrade)
1. Sign in as **`lab-operator@patchgate.lab`** (maker; password only). Choose Bank A. **Patches → New change request**: ring Ring0-Test, pick Firefox, PuTTY and the
   agent upgrade → submit.
2. The maker cannot approve their own request. Sign in as **`approver@bank-a.lab`** (bank checker) →
   **Change requests → the request → Approve**.
3. The next ticks run `connectorDeploy`, which creates `DEPLOY_PACKAGE` jobs. Every package is already in the
   site cache (pre-cached in the lab; otherwise `CACHE_PACKAGE` runs first). Watch with
   `docker logs -f bank-a-connector`. On the PC, Tactical runs **script id `installScriptId`** with
   `PG_REPO_URL=https://pg-cache…:8443/repo`. The PC downloads from the cache and re-checks SHA-256 and the
   Authenticode signer.
4. **Inventory confirms**: after `COLLECT` the request goes to *Completed*, Endpoints shows the new versions, and
   the agent reports 2.11.0.
5. **Audit** (UI) and the bank SIEM: `node lab/siem/check.mjs bank-a-connector-hq`. The CR create, approve and
   deploy events arrive through the connector relay.

## 5. Windows updates without WSUS
1. The real `wsusscn2.cab` (683 MB, Microsoft-signed) is **already in the Bank A cache**. With a PC present,
   the next tick queues `WU_SCAN`: script `wuScanScriptId` copies the cab from the cache (≈ 700 MB over the
   Sandbox NAT, then a scan of 5–20 min).
   Check: `docker logs bank-a-connector | grep -i wu_scan` → `ok:true`. The Patches page then lists the
   applicable Windows updates for that PC.
2. PatchGate fetches only the files the PC needs from Microsoft (verified + quarantined; the lab sets
   `QUARANTINE_HOURS=0`). This takes up to one hourly fetch, or run
   `curl -X POST --ssl-no-revoke --cacert lab/certs/out/ca.crt -H "x-worker-token: <WORKER_TOKEN from lab/patchgate/secrets.env>" https://patchgate.patchgate-lab.internal:3443/api/worker/fetch`.
3. Windows-update CR: the maker creates it (ring Ring0-Test, the KBs) and `approver@bank-a.lab` approves it.
   Then `CACHE_PACKAGE` runs for the .msu/.cab files and `WU_INSTALL` runs on the PC (wusa / DISM). Results:
   INSTALLED / PARTIAL / NOTHING_TO_DO, and a reboot follows the CR policy.

## 6. Stop
`bash lab/down-all.sh` (data kept). Closing the Sandbox window discards the PC. Re-run `make-sandbox.sh`
for a new one; the old agent stays in Tactical as offline, so delete it in Tactical if you want.
