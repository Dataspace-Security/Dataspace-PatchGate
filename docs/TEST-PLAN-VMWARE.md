# PatchGate — full feature test on VMware (bank server + bank PC)

| VM | Role | IP |
|---|---|---|
| Ubuntu 24.04 | **bank server**: PatchGate + Tactical + connector/cache (one-link install) | `<ubuntu-ip>` (fixed — see 0.0) |
| Windows 11 | **bank PC** (Tactical agent, patched only through PatchGate) | `<windows-ip>` |
| your PC (VMware host) | browser | — |

Tick each box; write the result (PASS / FAIL + screenshot) next to it. Test domain: `bank.test`.

---

## 0. Prepare (once)
- [ ] 0.0 Ubuntu has a **fixed IP**: `ip -4 addr show | grep inet` → note it as `<ubuntu-ip>`. Make it permanent (VMware → Edit →
      Virtual Network Editor → VMnet8 NAT → DHCP Settings, or a static address in `/etc/netplan/*.yaml` + `sudo netplan apply`).
      If the install ISO is still attached: VM → Settings → CD/DVD → untick "Connected" / "Connect at power on".
- [ ] 0.1 Ubuntu: remove the old test kit (it uses ports 443/8443):
      `bash /root/patchgate-test/Dataspace-PatchGate/kits/colleague-test/out/PatchGate-*-g668d166-test-kit/test-on-my-pc.sh --cleanup --yes`
      and `docker rm -f pgkit-edge`
- [ ] 0.2 Windows VM: uninstall the old Tactical agent (Settings → Apps → "Tactical RMM Agent" → Uninstall), it belonged to the old test site.
- [ ] 0.3 Your PC + Windows VM: in the hosts file remove the old `*.pgi.test` / `test-bank.pgi.test` lines.

## 1. Install (one link)
- [ ] 1.1 Ubuntu (as root): the one-link command printed in `docs/BANK-INSTALL.md` (`curl … installers/bank/install.sh | sudo bash -s -- --domain bank.test`).
- [ ] 1.2 Installer ends with: smoke test PASS, connector ACTIVE, Tactical reachable, **egress lockdown proven** (Tactical has no internet; only PatchGate's fetcher reaches Microsoft/vendors).
- [ ] 1.3 Note the logins file path and the PC-folder path it prints.
- [ ] 1.4 Your PC: add the hosts line the installer prints (`<ubuntu-ip> patchgate.bank.test rmm.bank.test api.bank.test mesh.bank.test pg-cache.bank.test`).
- [ ] 1.5 Open `https://patchgate.bank.test` → login page (accept the test certificate).

## 2. Sign-in and accounts (password only)
- [ ] 2.1 Sign in as Admin #1 (from the logins file) — **no 6-digit code** is asked.
- [ ] 2.2 First sign-in forces a new password (temporary password) — works.
- [ ] 2.3 5 wrong passwords → account locked → Admin unlocks it in Admin → Users.
- [ ] 2.4 Admin → Users: create an **Auditor** account; sign in as it in a private window.
- [ ] 2.5 Auditor sees everything but **no buttons** (Users, Settings, Patches, Change requests) — any change attempt is refused.
- [ ] 2.6 /account: change own password; other sessions are signed out.

## 3. Bank PC joins (one step)
- [ ] 3.1 Copy the PC folder (path from 1.3) to the Windows VM (`scp -r patch@<ubuntu-ip>:<pc-folder> C:\pc-kit`).
- [ ] 3.2 Double-click `C:\pc-kit\Install-PatchGateAgent.cmd` → accept admin prompt → last line **"OK - PC enrolled"**.
- [ ] 3.3 PatchGate → Endpoints → **Sync agents now** → the PC appears within ~1 minute (live refresh, no reload).
- [ ] 3.4 Endpoints shows correct OS, agent version, last seen (no negative times), **Windows Update: Locked**.
- [ ] 3.5 Assign the PC to **Ring0-Test**.

## 4. Windows Update lock (PatchGate is the only source)
- [ ] 4.1 Windows VM: Settings → Windows Update → "Check for updates" is hidden / managed by organisation.
- [ ] 4.2 Tactical (`https://rmm.bank.test`) → dashboard login is **blocked** (sealed) — see 7.
- [ ] 4.3 Windows VM (admin PowerShell): `Remove-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name WUServer` → next PatchGate scan shows **NOT locked** + alert (audit + notification). Re-run the PC installer → **Locked** again.
- [ ] 4.4 Defender definitions still update (Windows Security → Virus & threat protection → Protection updates → Check) — allowed by default.

## 5. Scan → patches
- [ ] 5.1 Endpoints → **Request scan of all PCs** → message "Syncing PCs, then scanning".
- [ ] 5.2 Within minutes: Missing / Critical counts filled; Last scan set (live refresh).
- [ ] 5.3 Patches → Windows updates the PC needs are listed and **selectable**; anything found only by Tactical is marked **"Needs PatchGate scan"** and not selectable.
- [ ] 5.4 Patches → third-party apps (catalogue from winget, verified Microsoft-signed index) are listed.

## 6. Change request → approval → deploy → progress
- [ ] 6.1 Admin #1: Patches → select 1 small update (e.g. Defender platform / MSRT) → create change request for **Ring0-Test** → submit.
- [ ] 6.2 Admin #1 tries to approve own request → **refused** (maker ≠ checker).
- [ ] 6.3 Admin #2 approves → status Approved.
- [ ] 6.4 Deploy → **progress bar** moves: files downloading → verifying → caching at site → installing → succeeded; Note column explains any wait.
- [ ] 6.5 Windows VM: the update is installed (Settings → Update history / `Get-HotFix`).
- [ ] 6.6 Reboot policy: request with "Reboot if required" → PC reboots only if needed.
- [ ] 6.7 Audit page: create / submit / approve / deploy events, hash chain **verified**.

## 7. Tactical sealed
- [ ] 7.1 `https://rmm.bank.test` → sign-in with any account is blocked (dashboard login disabled).
- [ ] 7.2 Ubuntu: break-glass on (`install-site.sh --break-glass on`, see BANK-INSTALL.md) → PatchGate shows an **alert** (Tactical activity, red badge) + notification.
- [ ] 7.3 With break-glass: approve an update inside Tactical (agent → Patches → Approve) → within ~30 seconds the approval is back to "not approved" in Tactical (refresh the Patches tab), and within ~1 minute PatchGate (Connectors → Tactical activity, source "approval guard (real time)") shows "Approval of KB… on DESKTOP-… reset automatically at hh:mm:ss UTC" + the break-glass login itself; one critical notification for the burst.
- [ ] 7.4 Break-glass off → alert; Admin acknowledges the alerts in PatchGate (audited).
- [ ] 7.5 Tactical's agent auto-update is OFF (agent stays on the approved version).

## 8. Approval switch (Admin only)
- [ ] 8.1 Advanced settings → Approvals → switch **Approval required OFF** (only Admins see the switch; Auditor cannot).
- [ ] 8.2 Amber note "Approval is OFF for this bank" on dashboard / change requests; audit + notification.
- [ ] 8.3 Admin #1 creates + submits a request → auto-approved → deploys without a second person.
- [ ] 8.4 Switch Approval required back **ON**; 6.2 behaviour returns.

## 9. Rollout safety
- [ ] 9.1 Advanced settings → Rings / maintenance windows visible; request outside a window waits (Note says why).
- [ ] 9.2 Emergency request (Advanced options) with approval ON needs **two different admins**.
- [ ] 9.3 Cancel a queued deployment → status cancelled, audited.

## 10. Agent version
- [ ] 10.1 Endpoints shows the agent version; an agent upgrade only happens through a PatchGate change request (AGENT_UPGRADE).

## 11. Reports, audit, operations
- [ ] 11.1 Reports → compliance report (CSV + printable) for the bank; SHA-256 shown.
- [ ] 11.2 Audit → verify chain → OK; export.
- [ ] 11.3 Operations → worker steps, connector health, queue sizes.
- [ ] 11.4 Notifications (if SMTP/webhook configured): events delivered; outbox visible.

## 12. Live / sync
- [ ] 12.1 Keep Endpoints and a change request open: they update by themselves ("Live · updated Xs ago").
- [ ] 12.2 Stop the Windows VM → after a while it shows offline / last seen; start it → back online.

## 13. Server operations
- [ ] 13.1 `install.sh --status` → all healthy.
- [ ] 13.2 Backup now (`--backup` or `docker compose … run --rm backup now`) → encrypted dump created; restore drill OK.
- [ ] 13.3 `install.sh --upgrade` after a new push → backup → migrate → rolling restart → still healthy, data kept.
- [ ] 13.4 Reboot the Ubuntu VM → everything comes back by itself.

## 14. Clean up (optional)
- [ ] 14.1 `install.sh --uninstall` (keeps data) / `--uninstall --purge` (asks first).

---
Report every FAIL with: step number, screenshot, and (Ubuntu) `install.sh --status` output.
