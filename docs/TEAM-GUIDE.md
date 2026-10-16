# PatchGate — Team guide: install in 3 steps

For our team (step 1) and bank IT (steps 2 and 3). One command per step. Details and background are in
[RUNBOOK.md](RUNBOOK.md); this page is the short version.

```
 Step 1  OUR server      install-patchgate.sh        PatchGate platform (web, database, signer, backups)
 Step 2  BANK site VM    install-site.sh             Tactical RMM (offline) + PatchGate Connector
 Step 3  BANK PCs        Install-PatchGateAgent.ps1  the agent, from the site's own package cache
```

The bank's Tactical server and PCs never use the internet. Only the site VM talks to us, outbound on port 443.

## Prerequisites

| | Step 1 — our server | Step 2 — bank site VM | Step 3 — bank PC |
|---|---|---|---|
| Machine | Ubuntu 22.04/24.04 or Debian 12, x86-64 | Linux x86-64 (Ubuntu/Debian/RHEL family) | Windows 10/11 or Server 2016+ |
| Size | 8 CPU, 16 GB RAM, 100 GB+ disk (min. 2 CPU / 8 GB / 20 GB) | 2–4 CPU, 8 GB RAM, 60 GB disk (min. 4 GB / 20 GB) | — |
| Network | public DNS name → this server; ports 80 + 443 free | outbound 443 to our PatchGate only; PCs → VM on 443 and 8443 | reaches the site VM on 443 + 8443 |
| Needs | root, internet (Docker + images) | root, `openssl`, `iptables`; Docker is installed for you if missing | local admin (or GPO startup script) |
| You get from us | — | site bundle **or** the one-line command, enrolment code, fingerprint | the PC folder made in step 2 |

## Step 1 — our PatchGate server (our team)

```bash
sudo installers/server/install-patchgate.sh
```

It asks for: the domain, the first admin's e-mail and name, the TLS certificate (your files, or self-signed for
a test), and where the images come from (registry + version, or build from source). Everything else is automatic:
Docker, secrets, configuration, database, start, health check, first admin, smoke test.

At the end it shows the **temporary admin password once** (it is not in the log). Sign in and set a new password (sign-in is
password-only).

> Screenshot placeholder: `docs/img/step1-summary.png` (installer summary)

Before go-live it lists what is still open (SIEM address, code-signing CA file, backup key off the server,
firewall rules). Automation: add `--non-interactive` and pass every answer as an option (`--help`).

## Step 2 — the bank site (bank IT)

In PatchGate: **Administration → Banks** (create the bank), then **Connectors → Add site**. PatchGate shows an
enrolment code (valid 24 h, single use) and the job-key **fingerprint**. Read the fingerprint to the bank on the
phone — it must match exactly.

Choose the variant that fits the site VM:

| Site VM | Command (as root) | Where software comes from |
|---|---|---|
| **No internet** (default) | `curl -fsSL https://<patchgate>/install/site.sh \| sudo bash -s -- --code <CODE> --fingerprint <FP>` — or from USB: `sudo ./install-site.sh --bundle patchgate-site-<ver>.tar.gz --bundle-key <KEY>` | everything from our server or the USB bundle (signature + SHA-256 checked) |
| **Has internet** | add `--online` to the same command | Tactical images from Docker Hub, pinned to the exact same versions; Docker from its official repository |

`<KEY>` is our bundle-signing key (`ed25519:…`, in `bundle-signing.pub.txt` of every release — keep a copy in
the team password manager). The web command has it built in and refuses a bundle that is not signed with it.

It asks for: the site name, the internal domain (it uses `rmm.`, `api.`, `mesh.` and `pg-cache.` under it), the
TLS certificate (the bank's own, or a test CA), and — on USB — the PatchGate address, code and fingerprint.
Then it starts Tactical, sets it up for PatchGate, connects the connector to us, and proves that Tactical and the
connector cannot reach the internet.

With `--online`, it then offers to **lock the VM's outbound traffic down to PatchGate only** (it shows the exact
firewall commands and applies them only if you answer `y`). Recommended. Either way, patches and updates come
only through PatchGate: Tactical and the PCs are never pointed at Microsoft Update or any other internet source.

At the end it shows the Tactical admin password once and the command for step 3.

> Screenshot placeholder: `docs/img/step2-connectors-add-site.png` (code + fingerprint in PatchGate)
> Screenshot placeholder: `docs/img/step2-summary.png` (installer summary)

Bank DNS: point `rmm`, `api`, `mesh` and `pg-cache.<domain>` to the site VM.

## Step 3 — the bank PCs (bank IT)

Copy `/opt/patchgate-site/pc/` from the site VM to a read-only share, then on each PC (admin PowerShell):

```powershell
powershell -ExecutionPolicy Bypass -File \\fs01\patchgate$\Install-PatchGateAgent.ps1 -ConfigFile \\fs01\patchgate$\patchgate-pc.json
```

Or simply double-click `Install-PatchGateAgent.cmd` in that folder (it asks for administrator rights and uses the
`patchgate-pc.json` next to it). It trusts the bank CA, adds hosts entries only for site names the bank's DNS does
not resolve (`siteIp` / `hostNames` in the JSON), checks the PC reaches the site's Tactical and package cache,
takes the agent from the site cache (or the copy in the folder), checks its SHA-256,
installs it, connects it to the site's Tactical and checks the service runs, then prints
`OK - PC enrolled, will appear in PatchGate within minutes` (or `FAILED - <reason>`). Already installed → it only
re-applies the Windows Update lock.

**Many PCs:** use it as a GPO computer startup script (same command; give "Domain Computers" read access to the
share). The install token in `patchgate-pc.json` expires (default 72 h): renew with
`sudo /opt/patchgate-site/runtime/install-site.sh --pc-token 720` and copy the file again.

> Screenshot placeholder: `docs/img/step3-gpo.png`

**PatchGate locks Windows Update on bank PCs.** The same script (at every run, also when the agent is already
installed) sets the Windows Update group policies so the PC never takes updates from Microsoft by itself: not
Windows' automatic updates, not "Check for updates", and not Tactical's own "Run Update Scan" / "Install
Approved Updates" (Windows Update points to a server that does not exist). Updates come only through PatchGate:
the offline scan with Microsoft's signed `wsusscn2.cab` and the approved update files from the site cache.
Defender virus definitions still update directly from Microsoft (signature data only, so protection stays
current); a bank that wants no internet traffic from PCs at all adds `-BlockDefenderDefinitionUpdates`. Every offline scan checks the lock; the Endpoints page shows **locked** / **NOT locked**
per PC and bank + platform admins get a "Windows Update NOT locked" notification when a PC loses it. Banks that
prefer GPO set the same values (RUNBOOK §6.2).

## Who does what (roles)

Two roles, the same for our team and inside every bank:

| Role | Platform (our team, `tenantId` empty) | Bank (`tenantId` set) |
|---|---|---|
| **Admin** (`ADMIN`) | everything, for every bank: banks, users, connectors, apps/patches, rings/windows, notification settings; raises change requests (maker); may be the **second** approver of a two-approver request | its own bank: settings; raises change requests **and approves them** (the bank's checker); sees its bank's users read-only |
| **Auditor** (`AUDITOR`) | read-only across every bank: banks, users, endpoints, patches, change requests, connectors, audit chains (incl. per-bank), reports/exports, operations | read-only within its bank: the same pages for its own bank |

**Accounts are ours.** Only a platform admin (our team) creates or changes user accounts — for our team and for
every bank: new users, name / role changes, deactivation, password reset, unlock. Bank admins and
bank auditors can only *see* their bank's user list; when a bank needs a new user, a leaver removed or a reset, it
asks its PatchGate administrator. (This keeps maker ≠ checker real: a bank admin cannot create a second admin
account for themselves.)

The normal flow is short: **pick patches → create the request → a bank admin approves → deploy.** Rings,
maintenance windows, emergency changes, notification rules and the approval policy are under **Advanced
settings** (sidebar) and the change request's **Advanced options**; the defaults work out of the box.
A request is never approved by the person who raised it, and (with approval ON, the default) always by an admin
of the bank itself. An admin can switch **Approval required** off for a bank (Advanced settings → Approval
policy): then a request is approved when it is submitted and can be deployed without a second person; the
dashboard and change-request pages show an amber "Approval is OFF" note, the switch is in the audit log and
every admin gets a notice. Keep it ON in production.

While a page is open it refreshes itself (top right: "Live · updated Xs ago" — every 5 s while something is
running, every 30 s otherwise, paused in a background tab). The change request shows a progress bar of the
rollout (finished %, succeeded / failed / in progress / queued) and each PC's stage: queued → files downloading /
verifying → caching at site → installing → reboot pending → succeeded / failed. The Endpoints page shows when
Tactical last saw each PC and when it booted ("unknown" when the PC clock is wrong, never a negative time).

## How to check it worked

| Step | Check | Good result |
|---|---|---|
| 1 | `sudo installers/server/install-patchgate.sh --status` | every service `healthy`; `/api/health -> 200` |
| 1 | sign in at `https://<domain>` | password change (first sign-in), then the dashboard |
| 2 | `sudo /opt/patchgate-site/runtime/install-site.sh --status` | connector `check` ends with `{"healthy":true}` |
| 2 | PatchGate → Connectors | the site is **online** (last seen < 1 min) |
| 3 | on the PC: `Get-Service tacticalrmm` | `Running`; log `C:\ProgramData\PatchGate\agent-install.log` ends with `done` |
| 3 | PatchGate → Endpoints (after the next sync) | the PC is listed under the bank and site |

## Top 10 problems

| # | Symptom | Fix |
|---|---|---|
| 1 | Step 1 stops at "port 80/443 already in use" | stop the other web server (`ss -ltnp`), run again |
| 2 | Step 1 smoke test fails "certificate valid for …" | the certificate does not cover the domain or the chain is incomplete; use the full chain file |
| 3 | Step 1 warns `siemExport=false` | set `SIEM_SYSLOG_URL` and `ca/siem-ca.pem` in `/opt/patchgate/deploy`, restart (RUNBOOK §4.1) |
| 4 | Step 2 "enrolment FAILED" | code older than 24 h or already used (make a new one), fingerprint typed wrong, or the site's public IP is not on our connector allow-list (RUNBOOK §6.4) |
| 5 | Step 2 "PatchGate is not reachable from the connector" | the bank firewall must allow the VM → our domain on 443 (and the domain must resolve, or use `--patchgate-ip`) |
| 6 | Step 2 "ISOLATION BROKEN" | a container reached the internet: do not continue; check that no one changed the compose files, send us the log |
| 7 | Step 2 waits a long time at "tactical-init" | normal on first start (up to 10 min); if it fails, `docker logs trmm-init` and run again |
| 8 | Step 3 "agent SHA-256 mismatch" | the file is wrong or damaged: never install it; re-copy the PC folder from the site VM |
| 9 | Step 3 "agent not available" | PatchGate has not cached the agent for this site yet and the PC folder has no agent copy: copy the full `pc/` folder |
| 10 | Step 3 "enrolment failed" / "token expired" | renew the token (`install-site.sh --pc-token 720`), copy `patchgate-pc.json` again; check the PC reaches `api.<domain>` on 443 |

Re-running any installer is safe: it keeps existing data, keys and settings. Logs:
`/var/log/patchgate-install.log` (step 1), `/var/log/patchgate-site-install.log` (step 2),
`C:\ProgramData\PatchGate\agent-install.log` (step 3).

## Upgrades and removal

| | Upgrade | Remove (keeps data) | Remove everything |
|---|---|---|---|
| Step 1 | `install-patchgate.sh --upgrade <version>` (backup → migrate → rolling restart → smoke test) | `--uninstall` | `--uninstall --purge` (asks to confirm) |
| Step 2 | `install-site.sh --upgrade <new bundle>` (add `--online` for online sites) | `--uninstall` | `--uninstall --purge` (then revoke the connector in PatchGate) |

## More detail

- Server sizing, configuration, firewall, backups, monitoring, key rotation: [RUNBOOK.md](RUNBOOK.md)
- Onboarding a bank, enrolment and fingerprints: [RUNBOOK.md §6](RUNBOOK.md#6-onboarding-a-bank-and-enrolling-connectors-high-level)
- Go-live order: [GO-LIVE-CHECKLIST.md](GO-LIVE-CHECKLIST.md) · Architecture: [ARCHITECTURE-HOSTED.md](ARCHITECTURE-HOSTED.md)
- Connector settings: `patchgate-connector/README.md` · One-line site install design: `installers/site/web-install.md`

## Tactical is sealed (short)

Nobody at the bank patches or installs through Tactical by hand. The site installer blocks the Tactical
dashboard login for every user (only PatchGate's service account works, via its API key) and sets every patch
policy to manual. `tacticaladmin` is a **break-glass** account for emergencies only:
`sudo /opt/patchgate-site/runtime/install-site.sh --break-glass on` … `--break-glass off`. Everything done in
Tactical outside PatchGate (logins, scripts, commands, approvals, setting changes) appears within about a
minute under **Connectors → Tactical activity** with a red badge, is sent to the bank's SIEM and e-mailed to
platform and bank admins (one alert per burst); update approvals PatchGate did not set are **reset automatically
within ~30 seconds** by the connector on the site ("Approval of KB… on DESKTOP-… reset automatically at
hh:mm:ss UTC"). An ADMIN acknowledges each
case. Root on the site VM can still bypass it — keep that access with named bank admins (RUNBOOK §13).

**PCs appear / scan now:** Endpoints → **Sync agents now** pulls new PCs from Tactical at once (otherwise every
15 minutes, `AGENT_SYNC_MINUTES`); **Request scan of all PCs** syncs first, then scans every PC and — when
Windows updates come through PatchGate — runs the offline Windows Update scan as soon as the Microsoft scan
catalog is verified and cached at the site.

## All-in-one bank server (short)

One bank, everything on one server inside the bank (PatchGate + Tactical + connector + cache), one link:
`curl -fsSL https://raw.githubusercontent.com/Dataspace-Security/Dataspace-PatchGate/main/installers/bank/install.sh | sudo bash -s -- --domain bank.local`.
Only PatchGate's fetcher reaches the internet; logins end up in `/opt/patchgate-bank/logins.txt` (root, 600);
PCs: copy `/opt/patchgate-site/pc/` and double-click `Install-PatchGateAgent.cmd`. Details: [BANK-INSTALL.md](BANK-INSTALL.md).
