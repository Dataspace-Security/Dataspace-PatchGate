#Requires -RunAsAdministrator
<#
  PatchGate lab — ONE-TIME host setup (run in an elevated PowerShell). Safe to re-run.
    1. hosts entries for the lab names (*.patchgate-lab.internal -> this PC)
    2. enable Windows Sandbox (the offline "bank PC"); a reboot is needed the first time
    3. firewall (private ranges only): 3443 = PatchGate (reached by the Bank A connector through Docker);
       443 + 8443 = Bank A site (Tactical ingress + connector package cache) for the Sandbox "bank PC".
       The Sandbox PC's OWN firewall (lab/sandbox/bootstrap.ps1) blocks it from PatchGate :3443.
  Undo: lab\host-setup.ps1 -Remove
#>
param(
    [string]$HostIp = '192.168.1.33',
    [switch]$Remove
)
$ErrorActionPreference = 'Stop'
$names = @('api', 'rmm', 'mesh', 'patchgate', 'siem', 'pg-cache') | ForEach-Object { "$_.patchgate-lab.internal" }
$hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
$marker = '# PatchGate lab'
$ruleName = 'PatchGate Lab - sandbox to PatchGate 3443'
$siteRule = 'PatchGate Lab - sandbox to Bank A site 443 8443'

$kept = Get-Content $hostsFile | Where-Object { $_ -notmatch [regex]::Escape($marker) }
if ($Remove) {
    Set-Content -Path $hostsFile -Value $kept -Encoding ASCII
    Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    Remove-NetFirewallRule -DisplayName $siteRule -ErrorAction SilentlyContinue
    Write-Output 'PatchGate lab host entries and firewall rule removed.'
    return
}

$entries = $names | ForEach-Object { "$HostIp`t$_`t$marker" }
Set-Content -Path $hostsFile -Value ($kept + $entries) -Encoding ASCII
Write-Output "hosts: $($names -join ', ') -> $HostIp"

Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Action Allow -Protocol TCP -LocalPort 3443 `
    -RemoteAddress '172.16.0.0/12', '192.168.0.0/16', '10.0.0.0/8' -Profile Any | Out-Null
Write-Output 'firewall: inbound TCP 3443 allowed from private ranges (Bank A connector -> PatchGate)'
Remove-NetFirewallRule -DisplayName $siteRule -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName $siteRule -Direction Inbound -Action Allow -Protocol TCP -LocalPort 443, 8443 `
    -RemoteAddress '172.16.0.0/12', '192.168.0.0/16', '10.0.0.0/8' -Profile Any | Out-Null
Write-Output 'firewall: inbound TCP 443, 8443 allowed from private ranges (sandbox PC -> Tactical + connector cache)'

$feature = Get-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM
if ($feature.State -ne 'Enabled') {
    Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -All -NoRestart | Out-Null
    Write-Output 'Windows Sandbox enabled — RESTART the PC once, then tell Claude to continue.'
} else {
    Write-Output 'Windows Sandbox already enabled.'
}
