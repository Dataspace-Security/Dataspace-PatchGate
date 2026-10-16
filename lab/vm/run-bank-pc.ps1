#Requires -RunAsAdministrator
<#
  PatchGate lab — turn a VirtualBox Windows 10/11 VM into the OFFLINE "bank PC" (same steps as the
  Windows Sandbox bootstrap, for hosts where Sandbox networking is unavailable).

  VirtualBox setup (host side, VM powered off):
    Network:        Adapter 1 = Bridged Adapter (the VM gets a 192.168.1.x address on your LAN)
    Shared folders: PGConfig -> <repo>\lab\sandbox\generated\config   (Read-only,  Auto-mount)
                    PGOut    -> <repo>\lab\sandbox\generated\out      (read-write, Auto-mount)
    Guest Additions installed in the VM (Devices > Insert Guest Additions CD image…), VM restarted.

  In the VM (PowerShell as Administrator):
    powershell -ExecutionPolicy Bypass -File \\VBOXSVR\PGConfig\run-bank-pc.ps1

  Progress + results are mirrored to PGOut every 10 s so the host can follow (results.tsv, bootstrap.log, DONE).
  Shared folders use the VirtualBox guest channel, not the network, so they keep working after the
  bootstrap locks the firewall to the lab host only.
#>
$ErrorActionPreference = 'Stop'
$share = '\\VBOXSVR'
$cfgSrc = Join-Path $share 'PGConfig'
$outDst = Join-Path $share 'PGOut'
$work = 'C:\PatchGateLab'

if (-not (Test-Path (Join-Path $cfgSrc 'lab.json'))) {
    throw "Shared folder $cfgSrc not found or empty. Check VirtualBox shared folder 'PGConfig' and Guest Additions."
}
if (-not (Test-Path $outDst)) { throw "Shared folder $outDst not found. Check VirtualBox shared folder 'PGOut' (read-write)." }

$ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -like '192.168.*' } | Select-Object -First 1).IPAddress
if (-not $ip) { Write-Warning 'No 192.168.x.x address: the VM network should be a Bridged Adapter on your LAN.' }
else { Write-Output "VM LAN address: $ip" }

Write-Output 'Copying lab configuration into the VM...'
New-Item -ItemType Directory -Force -Path "$work\config", "$work\out" | Out-Null
Remove-Item "$work\out\*" -Force -Recurse -ErrorAction SilentlyContinue
robocopy $cfgSrc "$work\config" /MIR /NFL /NDL /NJH /NJS /NP | Out-Null

Write-Output 'Running the bank-PC bootstrap (same as Windows Sandbox). This takes 5-10 minutes...'
$job = Start-Process -FilePath powershell.exe -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "$work\config\bootstrap.ps1") -PassThru -WindowStyle Normal

while (-not $job.HasExited) {
    robocopy "$work\out" $outDst /E /NFL /NDL /NJH /NJS /NP /R:1 /W:1 | Out-Null
    Start-Sleep -Seconds 10
}
robocopy "$work\out" $outDst /E /NFL /NDL /NJH /NJS /NP /R:1 /W:1 | Out-Null

Write-Output '--- results ---'
Get-Content "$work\out\results.tsv" -ErrorAction SilentlyContinue
Write-Output 'Done. Leave this VM running: PatchGate now manages it through Tactical + the site connector.'
