PatchGate lab - turn a spare PC into the test "Bank A PC"
=========================================================

What this does
--------------
This folder turns a spare Windows 10 or 11 PC into a pretend bank PC for the PatchGate test.
The PC is cut off from the internet and can only talk to the lab computer (the "lab host").
Some old versions of common programs are installed, and the Tactical agent is installed so
PatchGate can update them. Everything can be undone afterwards (see "How to undo").

Use a SPARE PC with nothing important on it. Do not use a work laptop you need tomorrow.


Before you start (prerequisites)
--------------------------------
1. The spare PC runs Windows 10 or Windows 11.
2. You can log in to it as an administrator.
3. It is connected to the SAME network as the lab host (address 192.168.1.x, same router / Wi-Fi).
4. The operator has the lab running on the lab host, including the firewall rules from
   lab\host-setup.ps1 (they allow the spare PC to reach the lab host on ports 443 and 8443).
5. The kit is fresh: it contains a one-day key. If it is older than 24 hours (see KIT-INFO.txt),
   ask the operator for a new one.


Steps
-----
1. Copy the whole "PatchGateBankPC" folder to the spare PC, for example from a USB stick to
   C:\PatchGateBankPC. (Running it straight from the USB stick also works.)

2. Click Start, type  PowerShell , right-click "Windows PowerShell" and choose
   "Run as administrator". Click "Yes" when Windows asks.

3. Type these two lines (press Enter after each). Change the folder if you copied it elsewhere:

      cd C:\PatchGateBankPC
      powershell -ExecutionPolicy Bypass -File .\Start-BankPC.ps1

4. Wait. It takes about 5 to 15 minutes. Lines starting with PASS or FAIL appear while it works.
   Do not close the window. Some windows may flash up while programs install - that is normal.

5. At the end you see a SUMMARY with the number of PASS and FAIL lines.
   - The results are copied into the "out" folder inside PatchGateBankPC.
   - Bring that "out" folder back to the operator (USB stick), or just tell them the summary.
   - If something says FAIL or STOPPED, tell the operator the exact line.

6. Leave the PC switched on and connected to the network until the operator says the test is done.


What it changes on the PC
-------------------------
Before changing anything it saves a backup in C:\PatchGateLab\backup. Then it:
- trusts the lab's test certificate (the "PatchGate Lab Root CA")
- adds 4 lines to the hosts file (names of the lab services -> the lab host address)
- turns the Windows Firewall on and BLOCKS ALL network traffic except to the lab host
  => this PC has NO INTERNET until you undo (no web browsing, no Windows Update, no email)
- installs old versions of some programs (Firefox, PuTTY, Git, 7-Zip, Zoom, VLC, Notepad++, ...)
- installs the Tactical RMM agent (the remote management agent PatchGate uses)
- keeps its files in C:\PatchGateLab (config, out, backup)


How to undo
-----------
Open PowerShell as administrator again (step 2) and type:

      powershell -ExecutionPolicy Bypass -File C:\PatchGateLab\config\Undo-BankPC.ps1

It removes the Tactical agent, removes the lab firewall rules, puts the firewall and the hosts file
back exactly as they were, and removes the lab certificate. It prints what it restored.
It is safe to run it twice. Restart the PC afterwards.

Want to see first what it would do, without changing anything?

      powershell -ExecutionPolicy Bypass -File C:\PatchGateLab\config\Undo-BankPC.ps1 -WhatIf

Not removed automatically: the old programs it installed (remove them in Settings > Apps if you
want) and the folder C:\PatchGateLab (delete it when the operator has the results).


Problems
--------
"STOPPED: ... not reachable"   The spare PC cannot reach the lab host. Check it is on the same
                               network (192.168.1.x) and ask the operator to check the lab is up.
"STOPPED: ... token expired"   The kit is older than 24 hours. Ask for a new kit.
"running scripts is disabled"  You typed only .\Start-BankPC.ps1 - use the full line from step 3.
"Access denied"                PowerShell was not started "as administrator" (step 2).
