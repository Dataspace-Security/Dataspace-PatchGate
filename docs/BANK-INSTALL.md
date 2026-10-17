# PatchGate — all-in-one bank server (one link)

Everything runs on **one Linux server inside the bank**: PatchGate, the official Tactical RMM + MeshCentral,
the PatchGate connector and the package cache. **Only PatchGate provides the updates**: its fetcher is the only
thing on the server that reaches the internet (Microsoft Update + vendor downloads through the squid allow-list).
Tactical, MeshCentral, the connector and the PCs have no internet.

The hosted multi-bank setup (TEAM-GUIDE steps 1–3) is unchanged; this page is the single-bank variant.

## What you need

| | |
|---|---|
| Server | Ubuntu 22.04 / 24.04 / 26.04 or Debian 12 / 13, x86-64. 4+ CPU, 16 GB RAM, 100 GB disk (minimum 2 CPU / 12 GB) |
| During the install | internet from the server (GitHub, Docker Hub, download.docker.com, microsoft.com) |
| Names | a bank internal domain, e.g. `bank.local`. Bank DNS: `patchgate`, `rmm`, `api`, `mesh`, `pg-cache` `.bank.local` → the server's LAN IP |
| TLS | the bank's certificate for those 5 names (+ key + root CA), **or** let the installer create a bank CA |
| PCs | reach the server on 443 and 8443 |
| **Fixed IP** | the server's LAN IP must **never change**: static IP, or a DHCP reservation (VMware: Virtual Network Editor → NAT → DHCP, or a static IP in Ubuntu's netplan). The router, the site's link to PatchGate, the PCs' hosts entries and `siteIp` in the PC folder all use it. If it does change: re-run the installer with `--lan-ip <new IP>`, then re-copy the PC folder to the PCs. |

## Install (one command)

```bash
curl -fsSL https://raw.githubusercontent.com/Dataspace-Security/Dataspace-PatchGate/main/installers/bank/install.sh \
  | sudo bash -s -- --domain bank.local
```

It asks for anything missing (bank name, the two admin accounts, …); `--non-interactive` uses the defaults.
Typical options:

```bash
sudo bash install.sh --domain bank.local --bank-name "Example Bank" \
  --admin1-email it.admin1@bank.local --admin2-email it.admin2@bank.local [--auditor-email audit@bank.local] \
  [--cert san.pem --key san.key --ca bank-root.pem] [--lan-ip 10.1.2.3] [--siem-url tls://siem.bank.local:6514 --siem-ca siem-ca.pem]
```

Re-running the same command is safe and resumes an interrupted install. Takes 30–60 minutes (images are built
from source on the server).

### What it does

1. Preflight (OS, CPU/RAM, base tools, Docker BuildKit), clones the public repository to `/opt/patchgate-bank/src`.
2. TLS: your certificate, or a new bank CA + one certificate for the 5 names (`/opt/patchgate-bank/tls/bank-ca.pem`).
3. Microsoft code-signing roots (Root CA 2011 + 2010) from microsoft.com, SHA-256 pinned, into `ca/codesign-ca.pem`.
4. PatchGate (`installers/server/install-patchgate.sh`): nginx on `127.0.0.1:8444` behind the router.
5. The bank (one tenant), **two bank ADMINs** (maker + checker) and optionally an AUDITOR, plus a platform
   operator account (connectors / enrolment). Temporary passwords, changed at first sign-in.
6. Bank site (`installers/site/install-site.sh --online`): official Tactical images from Docker Hub pinned by
   digest, on internal-only networks, bound to `127.0.0.2`; the site bundle is built locally (no download).
   It also installs the **Tactical NATS watchdog** (`patchgate-tactical-watchdog.timer`, every minute from 2 min
   after boot; cron where there is no systemd): after a reboot `trmm-nats` can lose a start-up race and Tactical
   then reaches no PC ("natsdown"). The watchdog restarts only `trmm-nats` (with back-off), logs to journald and
   reports to PatchGate, which alerts after 5 minutes (RUNBOOK §14 "Tactical messaging down").
7. SNI router `pg-bank-edge` (official nginx, TLS passthrough): `:443` → PatchGate or Tactical by name,
   `:8443` → package cache, `:80` → redirect.
8. Connector allow-list, enrolment code minted locally, connector enrolled with the job-signing key
   fingerprint pinned automatically.
9. Egress lockdown on the host (`DOCKER-USER` → chain `PG-BANK-EGRESS`): every container packet leaving via the
   uplink is dropped except the fetcher's egress proxy (tcp/443), its DNS and the bank SIEM. Persistent via
   `patchgate-bank-firewall.service`.
10. Self-check: smoke test, connector ACTIVE, Tactical login page through the router, raw-IP + DNS tests from
    every Tactical / site container must fail, the fetcher must reach the Microsoft catalog (and only allow-listed hosts).

### At the end

- URLs: `https://patchgate.<domain>`, `https://rmm.<domain>` (sealed Tactical, emergency only).
- Logins: `/opt/patchgate-bank/logins.txt` (root only, mode 600). Delete it once everyone has signed in.
- **Approval required** is ON by default for the bank: every change needs the second ADMIN (maker ≠ checker).
  An ADMIN can switch it per bank in Administration → Banks.
- Health summary: smoke PASS, connector ACTIVE, Tactical reachable, NATS watchdog active, egress lockdown proven.

## Bank PCs (one step)

1. Copy `/opt/patchgate-site/pc/` to a read-only share or a USB stick.
2. On each PC double-click **Install-PatchGateAgent.cmd** (asks for admin rights). Equivalent:
   `powershell -ExecutionPolicy Bypass -File <folder>\Install-PatchGateAgent.ps1 -ConfigFile <folder>\patchgate-pc.json`

The kit carries `bank-ca.pem`, the server's LAN IP (`siteIp`) and the 5 host names (hosts entries are written
only where DNS does not resolve them). The install token lasts 72 h:
`sudo /opt/patchgate-site/runtime/install-site.sh --pc-token`, then re-run the bank installer to refresh `siteIp`.

A PC that still has a Tactical agent from an earlier test: the `.cmd` re-points it; if the PC keeps showing
the old site, uninstall the old agent first (admin cmd), then run the `.cmd` again:
`"C:\Program Files\TacticalAgent\unins000.exe" /VERYSILENT` and `"C:\Program Files\Mesh Agent\MeshAgent.exe" -fulluninstall`.

Admin browser without bank DNS: the installer prints the hosts-file line (`<LAN IP> patchgate.<d> rmm.<d> api.<d>
mesh.<d> pg-cache.<d>`) and where to import `bank-ca.pem`, plus a numbered "test now" list.

A server that still runs the colleague test kit (`pgkit-*` containers) is refused with the cleanup command
(`bash <kit>/test-on-my-pc.sh --cleanup --yes`); nothing is removed automatically.

## Later

```bash
sudo /opt/patchgate-bank/src/installers/bank/install.sh --status
sudo /opt/patchgate-bank/src/installers/bank/install.sh --upgrade [--ref v1.1.0]   # pull -> rebuild -> backup -> migrate -> rolling restart
sudo /opt/patchgate-bank/src/installers/bank/install.sh --uninstall [--purge]      # keeps data unless --purge (confirm)
```

- Go-live: set `QUARANTINE_HOURS=48` in `/opt/patchgate/deploy/.env.production` (default 0), then `--upgrade`.
- Upgrades lift the egress lockdown only while images are built, then re-apply and re-prove it.
- Bank DNS should carry the 5 names; the installer adds a marked `/etc/hosts` line on the server itself only.
- After a server reboot nothing has to be started by hand: Docker restarts the containers, the firewall unit
  re-applies the lockdown and the NATS watchdog fixes Tactical's message bus within ~1-2 minutes
  (`journalctl -t patchgate-tactical-watchdog`; `--status` shows it).

## Notes

- Through the router PatchGate sees the Docker gateway as the source address. The router admits only the bank's
  internal ranges (`--allow-cidrs`, default RFC 1918 + loopback); connector requests stay Ed25519-signed.
- The bank CA made by the installer issues an 825-day certificate; renew before it expires (or use the bank's PKI).
- Developers: `installers/bank/test/dind-test.sh` runs the whole install in one privileged Docker container
  with the local working tree (`--source-dir`).
