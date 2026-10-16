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

## Option A: from GitHub (recommended)

One script clones the private repository, **builds PatchGate from source** on your PC and installs everything.
You need access to `Dataspace-Security/Dataspace-PatchGate`: either the GitHub CLI signed in (`gh auth login`),
or a read-only fine-grained token (Repository access: that repo; Permissions: Contents = Read).

```bash
# in Git Bash (Windows) or a terminal (Linux), in an empty folder:
gh api -H "Accept: application/vnd.github.raw" \
  "repos/Dataspace-Security/Dataspace-PatchGate/contents/kits/colleague-test/install-patchgate-test.sh?ref=main" \
  > install-patchgate-test.sh
bash install-patchgate-test.sh            # clone -> build images -> install (60-120 minutes the first time)
```

Without the GitHub CLI (the token is typed, not shown; the script asks for it again for the clone):

```bash
read -rs GH_TOKEN && curl -fsSL -H "Authorization: Bearer $GH_TOKEN" -H "Accept: application/vnd.github.raw" \
  "https://api.github.com/repos/Dataspace-Security/Dataspace-PatchGate/contents/kits/colleague-test/install-patchgate-test.sh?ref=main" \
  -o install-patchgate-test.sh; unset GH_TOKEN
bash install-patchgate-test.sh
```

Later: `bash install-patchgate-test.sh --status`, `--code approver`, `--reinstall` (erase + install fresh),
`--cleanup`. Options: `--ref <branch|tag|commit>` (default `main`), `--dir <folder>` (default `~/patchgate-test`).
The clone, build logs and the kit (with `logins.txt`) live under `~/patchgate-test/`.

## Option B: offline kit folder (someone gave you `PatchGate-<version>-test-kit`)

Uses the release images inside the folder (no build). Open **Git Bash** (Windows) or a terminal (Linux) in that
folder, then:

```bash
./test-on-my-pc.sh            # 1. installs everything (30-90 minutes, mostly downloads)
./test-on-my-pc.sh --status   # 2. any time: is it running? is the connector healthy?
./test-on-my-pc.sh --cleanup  # 3. when you are done: removes everything the kit created
```

**Start over** (erase the test install and install it fresh, in one command):

```bash
./test-on-my-pc.sh --reinstall          # shows what it will erase and asks y/N; add --yes to skip the question
```

It erases **only** what the kit created (containers `pgkit-server` / `pgkit-site`, network `pgkit-net`, volumes
`pgkit-*` — each one checked for the kit's label `com.patchgate.kit=colleague-test`). Your other containers,
networks, volumes and images are never touched. Running the plain command again on a finished install only
prints the address and these options; on an interrupted install it continues where it stopped.

**From the PatchGate project instead of a copied kit** (e.g. on a developer PC, also next to the running lab —
the kit uses its own containers `pgkit-*`, its own network and a free host port such as 9443+):

```bash
cd /d/Projects/Dataspace_Security/Dataspace-PatchGate          # the repository root
bash kits/colleague-test/build-kit.sh "$(cat VERSION)"         # needs release/out/<version>/ (release build)
cd "kits/colleague-test/out/PatchGate-$(cat VERSION)-test-kit"
./test-on-my-pc.sh              # first time
./test-on-my-pc.sh --reinstall  # start over (erases only the kit, asks first)
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

`logins.txt` lists the four test accounts with their passwords. Every sign-in also asks for a 6-digit code:

```bash
./test-on-my-pc.sh --code approver      # or: platform-admin | bank-admin | viewer
```

(or add the TOTP secret from `logins.txt` to Microsoft/Google Authenticator as a "setup key").
A code works only once — if refused, wait 30 seconds and take the next one.

| Account | Who it is |
|---|---|
| platform-admin `admin@pgi.test` | our team's administrator (all banks); raises the test change request |
| bank-admin `admin@test-bank.test` | Test Bank's administrator (only Test Bank) |
| approver `approver@test-bank.test` | Test Bank's approver: every change needs the bank's yes |
| viewer `viewer@test-bank.test` | Test Bank read-only user |

## What to try

The kit has already checked these rules once through the real API (two requests titled "Kit check").

1. **platform-admin**: Patches → **TEST FIXTURE – sample Windows update** (KB0000001; a test PC has no real bank
   PCs reporting updates) → create a change request for Test Bank and submit it.
2. Still **platform-admin**: try to approve it → **refused** (maker ≠ checker, and a bank approver is always required).
3. **approver**: approve it → the change is released for Test Bank.
4. **platform-admin** → Connectors: site "Head office" of Test Bank is **ACTIVE / online**.
5. Audit page: sign-ins, approvals, the site enrolment and the bundle download are all recorded.
6. **bank-admin** → Administration → Users: sees only Test Bank's users. **viewer** can look, not change.

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
   `production.cloudflare.docker.com`, `download.docker.com`, `archive.ubuntu.com`, `security.ubuntu.com`. Then run the script again (it resumes).
5. **Certificate warning in the browser** — expected (self-signed test CA): Advanced → Continue.

Anything else: run the script again — it resumes where it stopped. To start fresh: `--cleanup`, then run it
again. Send `logs/` (no passwords in it) to the PatchGate team if you are stuck. Do **not** send `logins.txt`.
