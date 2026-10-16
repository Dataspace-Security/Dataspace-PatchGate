# Bank A PC on a spare physical PC (operator checklist)

Use this when Windows Sandbox and VirtualBox are not usable on the lab host (Hyper-V networking bug / slow
mode). A spare Windows 10/11 PC on the same LAN plays the Bank A PC. It runs the **same** `bootstrap.ps1`
as the Sandbox, so the results and the PASS lines are the same as in `lab/sandbox/AFTER-RESTART.md` §2.

## 0. Prerequisites
- Lab host (192.168.1.33) has run `lab\host-setup.ps1` once (inbound 443 + 8443 from private ranges).
- Spare PC: Windows 10/11, admin account, same LAN (192.168.1.x), nothing important on it. Its firewall
  is locked down to the lab host until the undo, so it has **no internet** during the test.
- Domain-joined PCs: a firewall GPO can override the local lock-down. Use a non-domain PC.

## 1. Build the kit (lab host, Git Bash, repo root)
```bash
bash lab/up-all.sh                    # Tactical, connector + cache, PatchGate, scheduler
bash lab/pc-kit/build-kit.sh 2.10.0   # fresh 24 h install token; ~630 MB with the outdated apps
#   --no-fixtures  -> kit without the outdated apps (~1 MB)
```
Output: `lab/pc-kit/generated/PatchGateBankPC/` (gitignored, it holds the install token). Copy the whole
folder to a USB stick. `KIT-INFO.txt` shows the token expiry: rebuild after 24 h or for another PC.

## 2. On the spare PC (the user follows README.txt in the kit)
```powershell
# elevated PowerShell, in the copied folder
powershell -ExecutionPolicy Bypass -File .\Start-BankPC.ps1
```
1. Pre-flight (nothing changed if it fails): admin, Windows 10/11, a 192.168.1.x address, lab host
   reachable on 443 + 8443, token not expired.
2. Backup to `C:\PatchGateLab\backup` (once; a re-run keeps the original): hosts file, firewall profile
   settings (enabled + default inbound/outbound per profile), existing `PatchGateLab-*` rules, whether the
   lab CA / a Tactical agent / Defender exclusions already existed.
3. Copies the kit to `C:\PatchGateLab\config`, runs `bootstrap.ps1` (results in `C:\PatchGateLab\out`).
4. Copies `out` back into the kit folder (`PatchGateBankPC\out`) and prints a PASS/FAIL summary.

## 3. Check the results (lab host)
```bash
column -t -s $'\t' /path/to/usb/PatchGateBankPC/out/results.tsv   # every line PASS
cat /path/to/usb/PatchGateBankPC/out/pc-info.tsv                  # PC name, IP, OS
docker logs bank-a-connector | grep 'GET /repo/tactical/agent'     # one agent download from the cache
```
The expected lines are listed in `lab/sandbox/AFTER-RESTART.md` §2. Then continue with §3–§5 there
(sync → discovery → maker/checker deploy → Windows updates). The PC shows up under its real hostname.

## 4. Undo (spare PC, elevated PowerShell)
```powershell
powershell -ExecutionPolicy Bypass -File C:\PatchGateLab\config\Undo-BankPC.ps1 -WhatIf   # dry run
powershell -ExecutionPolicy Bypass -File C:\PatchGateLab\config\Undo-BankPC.ps1
```
Uninstalls the Tactical agent (silent Inno uninstaller), removes `PatchGateLab-*` firewall rules, restores
the firewall profiles and the hosts file from the backup (if the hosts file was edited since, only the kit's
lines are removed), removes the lab CA from `LocalMachine\Root` by thumbprint, and removes the Tactical
Defender exclusions the agent added. Anything that existed before the kit (backup flags) is left alone.
Safe to run twice: a completed undo archives the backup as `backup-undone-<time>`.
Not undone: the outdated apps (Settings > Apps) and the PC's entry in Tactical (delete it there).
