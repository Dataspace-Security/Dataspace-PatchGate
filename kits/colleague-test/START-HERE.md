# PatchGate test kit — try the whole system on your own PC

**This is a TEST setup.** Everything runs on your one PC inside Docker: the PatchGate server, one bank site
(Tactical RMM + PatchGate Connector) and the test accounts. It uses a self-signed test certificate and a
throwaway signing key. It is **not** how a bank is installed — for that see `docs/TEAM-GUIDE.md` in the
PatchGate repository.

## What you need

- **Windows 10/11** with **Docker Desktop** (WSL2 engine) and **Git for Windows** (for "Git Bash"),
  or **Linux** with Docker Engine.
- **16 GB RAM** (12 GB minimum for Docker), **20 GB free disk**, **internet** (Docker Hub and
  download.docker.com are used).
- Administrator rights **once**, to add one line to the hosts file.

## The 3 commands

Open **Git Bash** (Windows) or a terminal (Linux) in this folder, then:

```bash
./test-on-my-pc.sh            # 1. installs everything (25-40 minutes, mostly downloads)
./test-on-my-pc.sh --status   # 2. any time: is it running? is the connector healthy?
./test-on-my-pc.sh --cleanup  # 3. when you are done: removes everything the kit created
```

At the end the script prints the address, e.g. `https://patchgate.pgi.test/` (or with a port such as
`:9443` if 443 is busy on your PC), and writes **`logins.txt`** into this folder.

**Hosts line (once, as Administrator).** Windows: start PowerShell with "Run as administrator" and run:

```powershell
Add-Content -Path $env:windir\System32\drivers\etc\hosts -Value "`r`n127.0.0.1 patchgate.pgi.test"
```

Linux: `echo "127.0.0.1 patchgate.pgi.test" | sudo tee -a /etc/hosts`

The browser will warn about the certificate (test CA): click **Advanced → Continue**. (Optional: import
`patchgate-test-ca.pem` from this folder as a trusted root to avoid the warning; remove it afterwards.)

## Sign in

`logins.txt` lists four accounts with their passwords. Every sign-in also asks for a 6-digit code:

```bash
./test-on-my-pc.sh --code approver      # or: platform-admin | operator | bank-admin
```

(or add the TOTP secret from `logins.txt` to Microsoft/Google Authenticator as a "setup key").
A code works only once — if refused, wait 30 seconds and take the next one.

| Account | Who it is |
|---|---|
| platform-admin `admin@pgi.test` | our team's administrator (all banks) |
| operator `operator@pgi.test` | our team's operator: raises change requests |
| bank-admin `admin@test-bank.test` | Test Bank's administrator |
| approver `approver@test-bank.test` | Test Bank's approver: every change needs the bank's yes |

## What to try

1. **operator**: Patches → pick an update → create a change request for Test Bank.
2. **platform-admin**: try to approve it → **refused** (a bank approver is always required).
3. **approver**: approve it → the change is released for Test Bank.
4. **platform-admin** → Connectors: site "Head office" of Test Bank is **ACTIVE / online**.
5. Audit page: sign-ins, approvals, the site enrolment and the bundle download are all recorded.
6. **bank-admin** → Administration → Users: sees only Test Bank's users.

## Clean up

`./test-on-my-pc.sh --cleanup` removes only the kit's containers (`pgkit-server`, `pgkit-site`), its network
and volumes. Logs in `logs/` stay. Remove the hosts line again (PowerShell as Administrator):

```powershell
(Get-Content $env:windir\System32\drivers\etc\hosts) -notmatch 'patchgate\.pgi\.test' | Set-Content $env:windir\System32\drivers\etc\hosts
```

## Troubleshooting (top 5)

1. **"Docker is not running"** — start Docker Desktop, wait for "Engine running", run the script again.
2. **"not enough memory"** — Docker Desktop → Settings → Resources → Memory ≥ 12 GB (16 GB better). With the
   WSL2 engine the limit is in `%UserProfile%\.wslconfig` (`[wsl2]` / `memory=16GB`), then `wsl --shutdown`.
3. **"port in use"** — the script picks the next free port (9443, 10443, …) and prints it; use that address.
4. **Corporate proxy blocks Docker Hub / download.docker.com** — set the proxy in Docker Desktop → Settings →
   Resources → Proxies, or ask IT to allow `registry-1.docker.io`, `auth.docker.io`,
   `production.cloudflare.docker.com`, `download.docker.com`. Then run the script again (it resumes).
5. **Certificate warning in the browser** — expected (self-signed test CA): Advanced → Continue.

Anything else: run the script again — it resumes where it stopped. To start fresh: `--cleanup`, then run it
again. Send `logs/` (no passwords in it) to the PatchGate team if you are stuck. Do **not** send `logins.txt`.
