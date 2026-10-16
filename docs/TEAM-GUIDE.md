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

At the end it shows the **temporary admin password once** (it is not in the log). Sign in, set a new password and
set up the authenticator app.

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

It trusts the bank CA, takes the agent from the site cache (or the copy in the folder), checks its SHA-256,
installs it, connects it to the site's Tactical and checks the service runs. Already installed → it does nothing.

**Many PCs:** use it as a GPO computer startup script (same command; give "Domain Computers" read access to the
share). The install token in `patchgate-pc.json` expires (default 72 h): renew with
`sudo /opt/patchgate-site/runtime/install-site.sh --pc-token 720` and copy the file again.

> Screenshot placeholder: `docs/img/step3-gpo.png`

## Who does what (roles)

Two roles, the same for our team and inside every bank:

| Role | Platform (our team, `tenantId` empty) | Bank (`tenantId` set) |
|---|---|---|
| **Admin** (`ADMIN`) | everything, for every bank: banks, users, connectors, apps/patches, rings/windows, notification settings; raises change requests (maker); may be the **second** approver of a two-approver request | its own bank: users, settings; raises change requests **and approves them** (the bank's checker) |
| **Auditor** (`AUDITOR`) | read-only across every bank: banks, users, endpoints, patches, change requests, connectors, audit chains (incl. per-bank), reports/exports, operations | read-only within its bank: the same pages for its own bank |

The normal flow is short: **pick patches → create the request → a bank admin approves → deploy.** Rings,
maintenance windows, emergency changes, notification rules and the approval policy are under **Advanced
settings** (sidebar) and the change request's **Advanced options**; the defaults work out of the box.
A request is never approved by the person who raised it, and always by an admin of the bank itself.

## How to check it worked

| Step | Check | Good result |
|---|---|---|
| 1 | `sudo installers/server/install-patchgate.sh --status` | every service `healthy`; `/api/health -> 200` |
| 1 | sign in at `https://<domain>` | password change + authenticator set-up (unless `AUTH_MFA=off`), then the dashboard |
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
