#Requires -Version 5.1
<#
  PatchGate lab - turn a SPARE physical Windows 10/11 PC (same LAN as the lab host) into the offline
  "Bank A PC". Run from the copied kit folder (e.g. a USB stick) in an ELEVATED PowerShell:

      powershell -ExecutionPolicy Bypass -File .\Start-BankPC.ps1            (all steps)
      powershell -ExecutionPolicy Bypass -File .\Start-BankPC.ps1 -NoFixtures (skip the outdated test apps)

  1. pre-flight: admin, Windows 10/11, LAN address, lab host reachable on 443 + 8443, install token valid
     (nothing is changed if a check fails)
  2. BACKUP (once, before any change) -> C:\PatchGateLab\backup\
       hosts file, firewall profile settings (enabled + default inbound/outbound action per profile),
       existing "PatchGateLab-*" firewall rules, whether the lab CA / Tactical agent / Defender exclusions
       already existed
  3. copy the kit to C:\PatchGateLab\config (bootstrap.ps1 reads it there)
  4. run bootstrap.ps1 (same script as the Windows Sandbox): lab CA, hosts, firewall lock-down,
     isolation proofs, outdated apps, Tactical agent from the site cache -> C:\PatchGateLab\out
  5. copy C:\PatchGateLab\out back into the kit folder (out\) and print a summary

  Undo everything: Undo-BankPC.ps1 (in the kit folder or C:\PatchGateLab\config).
#>
[CmdletBinding()]
param(
    [switch]$NoFixtures,
    [switch]$SkipPreflight
)
$ErrorActionPreference = 'Stop'

$kit = $PSScriptRoot
$root = 'C:\PatchGateLab'
$cfgDir = Join-Path $root 'config'
$outDir = Join-Path $root 'out'
$backupDir = Join-Path $root 'backup'
$kitCfg = Join-Path $kit 'config'
$kitOut = Join-Path $kit 'out'
$hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
$agentDir = 'C:\Program Files\TacticalAgent'

function Say($msg) { Write-Host $msg }
function Stop-Kit($msg) {
    Write-Host ''
    Write-Host "STOPPED: $msg" -ForegroundColor Red
    Write-Host 'Nothing on this PC was changed by this step. Tell the operator the message above.'
    exit 1
}

# ------------------------------------------------------------------ 1. pre-flight (read-only)
Say '==== PatchGate lab: spare PC -> Bank A PC ===='
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Stop-Kit 'Run PowerShell as Administrator (right-click > Run as administrator).' }
if (-not (Test-Path (Join-Path $kitCfg 'lab.json'))) { Stop-Kit "Kit incomplete: $kitCfg\lab.json not found. Copy the WHOLE PatchGateBankPC folder." }
foreach ($f in @('bootstrap.ps1', 'ca.crt')) {
    if (-not (Test-Path (Join-Path $kitCfg $f))) { Stop-Kit "Kit incomplete: $kitCfg\$f not found." }
}
$cfg = Get-Content (Join-Path $kitCfg 'lab.json') -Raw | ConvertFrom-Json
$hostIp = $cfg.hostIp

if (-not $SkipPreflight) {
    $os = Get-CimInstance Win32_OperatingSystem
    Say "Windows: $($os.Caption) build $($os.BuildNumber)"
    if ([int]$os.BuildNumber -lt 10240 -or $os.ProductType -ne 1) { Stop-Kit 'This kit needs Windows 10 or 11 (desktop edition).' }

    $prefix = ($hostIp -split '\.')[0..2] -join '.'
    $myIp = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -like "$prefix.*" } | Select-Object -First 1
    if (-not $myIp) { Stop-Kit "This PC has no $prefix.x address. Connect it to the same network (LAN/Wi-Fi) as the lab host $hostIp." }
    Say "This PC: $($myIp.IPAddress) (lab host $hostIp)"

    foreach ($port in $cfg.allowedPorts) {
        $tcp = Test-NetConnection -ComputerName $hostIp -Port ([int]$port) -WarningAction SilentlyContinue -InformationLevel Quiet
        if (-not $tcp) { Stop-Kit "Lab host ${hostIp}:$port is not reachable. On the lab host: lab up (bash lab/up-all.sh) and lab\host-setup.ps1 firewall rules." }
        Say "Lab host ${hostIp}:$port reachable"
    }

    $expires = [DateTimeOffset]::Parse($cfg.installTokenExpiresAt)
    if ($expires -lt [DateTimeOffset]::UtcNow.AddMinutes(30)) {
        Stop-Kit "The Tactical install token in this kit expired (or expires within 30 min): $($cfg.installTokenExpiresAt). Ask the operator for a new kit (bash lab/pc-kit/build-kit.sh)."
    }
    Say "Install token valid until $($cfg.installTokenExpiresAt)"
}

# ------------------------------------------------------------------ 2. backup (once; never overwritten)
$backupFile = Join-Path $backupDir 'backup.json'
if (Test-Path $backupFile) {
    Say "Backup already exists ($backupDir) - keeping the ORIGINAL state from the first run."
} else {
    Say "Backing up current settings -> $backupDir"
    New-Item -ItemType Directory -Force -Path $backupDir | Out-Null
    Copy-Item -LiteralPath $hostsFile -Destination (Join-Path $backupDir 'hosts.bak') -Force

    $profiles = @(Get-NetFirewallProfile -PolicyStore PersistentStore | ForEach-Object {
            [ordered]@{
                Name                  = "$($_.Name)"
                Enabled               = "$($_.Enabled)"
                DefaultInboundAction  = "$($_.DefaultInboundAction)"
                DefaultOutboundAction = "$($_.DefaultOutboundAction)"
            } })
    $rulesBefore = @(Get-NetFirewallRule -DisplayName 'PatchGateLab-*' -ErrorAction SilentlyContinue |
        ForEach-Object { [ordered]@{ Name = "$($_.Name)"; DisplayName = "$($_.DisplayName)"; Direction = "$($_.Direction)"; Action = "$($_.Action)" } })

    $caCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2((Join-Path $kitCfg 'ca.crt'))
    $caThumb = $caCert.Thumbprint
    $caExisted = Test-Path "Cert:\LocalMachine\Root\$caThumb"
    $agentExisted = (Test-Path (Join-Path $agentDir 'tacticalrmm.exe')) -or [bool](Get-Service -Name tacticalrmm -ErrorAction SilentlyContinue)
    $exclusions = @()
    try { $exclusions = @((Get-MpPreference -ErrorAction Stop).ExclusionPath | Where-Object { $_ }) } catch { $exclusions = @() }

    $backup = [ordered]@{
        createdAt              = (Get-Date).ToUniversalTime().ToString('o')
        computerName           = $env:COMPUTERNAME
        hostIp                 = $hostIp
        hostNames              = @($cfg.hostNames)
        hostsFile              = 'hosts.bak'
        firewallProfiles       = $profiles
        patchgateRulesBefore   = $rulesBefore
        caThumbprint           = $caThumb
        caSubject              = $caCert.Subject
        caPreExisting          = $caExisted
        agentPreExisting       = $agentExisted
        defenderExclusionPaths = $exclusions
    }
    $backup | ConvertTo-Json -Depth 5 | Set-Content -Path $backupFile -Encoding UTF8
    $profiles | ForEach-Object { [pscustomobject]$_ } | Format-Table -AutoSize | Out-String | Write-Host
    if ($caExisted) { Say 'Note: the lab CA was already trusted before this run (Undo will leave it).' }
    if ($agentExisted) { Say 'Note: a Tactical agent was already installed before this run (Undo will leave it).' }
}

# ------------------------------------------------------------------ 3. copy kit -> C:\PatchGateLab\config
Say "Copying the kit to $cfgDir"
New-Item -ItemType Directory -Force -Path $cfgDir, $outDir | Out-Null
$xf = @()
if ($NoFixtures) { $xf = @('/XF', 'fixtures.json', '/XD', 'fixtures') }
robocopy $kitCfg $cfgDir /MIR /NFL /NDL /NJH /NJS /NP @xf | Out-Null
if ($LASTEXITCODE -ge 8) { Stop-Kit "Copy to $cfgDir failed (robocopy exit $LASTEXITCODE)." }
foreach ($f in @('Start-BankPC.ps1', 'Undo-BankPC.ps1', 'README.txt', 'KIT-INFO.txt')) {
    $src = Join-Path $kit $f
    if (Test-Path $src) { Copy-Item -LiteralPath $src -Destination $cfgDir -Force }
}
if ($NoFixtures) { Say 'Outdated test apps: SKIPPED (-NoFixtures).' }
Get-ChildItem -LiteralPath $outDir -Force | Remove-Item -Recurse -Force

# ------------------------------------------------------------------ 4. bootstrap (same as the Sandbox)
Say ''
Say 'Running the bank-PC setup. This takes 5-15 minutes. From now on this PC has NO internet until you run Undo-BankPC.ps1.'
$bootstrap = Join-Path $cfgDir 'bootstrap.ps1'
$proc = Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
    -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$bootstrap`"") -PassThru -WindowStyle Minimized
$results = Join-Path $outDir 'results.tsv'
$shown = 0
while (-not $proc.HasExited) {
    Start-Sleep -Seconds 5
    if (Test-Path $results) {
        $lines = @(Get-Content $results)
        for ($i = $shown; $i -lt $lines.Count; $i++) { Say "  $($lines[$i])" }
        $shown = $lines.Count
    }
}
if (Test-Path $results) {
    $lines = @(Get-Content $results)
    for ($i = $shown; $i -lt $lines.Count; $i++) { Say "  $($lines[$i])" }
}

# ------------------------------------------------------------------ 5. results back to the kit + summary
$info = @(
    "computer`t$env:COMPUTERNAME",
    "ip`t$((Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } | ForEach-Object IPAddress) -join ',')",
    "os`t$((Get-CimInstance Win32_OperatingSystem).Caption) $((Get-CimInstance Win32_OperatingSystem).BuildNumber)",
    "finished`t$((Get-Date).ToString('o'))",
    "backup`t$backupDir"
)
$info | Set-Content -Path (Join-Path $outDir 'pc-info.tsv') -Encoding ASCII

$copied = $false
try {
    New-Item -ItemType Directory -Force -Path $kitOut | Out-Null
    robocopy $outDir $kitOut /E /NFL /NDL /NJH /NJS /NP /R:1 /W:1 | Out-Null
    $copied = $LASTEXITCODE -lt 8
} catch { $copied = $false }

$all = @()
if (Test-Path $results) { $all = @(Get-Content $results) }
$passed = @($all | Where-Object { $_ -like 'PASS*' }).Count
$failed = @($all | Where-Object { $_ -like 'FAIL*' })
Say ''
Say '==================== SUMMARY ===================='
Say "PASS: $passed   FAIL: $($failed.Count)"
foreach ($l in $failed) { Write-Host "  $l" -ForegroundColor Red }
if ($all.Count -eq 0) { Write-Host '  No results were written - see C:\PatchGateLab\out\bootstrap.log' -ForegroundColor Red }
if ($copied) { Say "Results copied to: $kitOut   (bring this folder back to the operator)" }
else { Write-Host "Could not copy results to $kitOut - take C:\PatchGateLab\out instead." -ForegroundColor Yellow }
Say "Full log: $outDir\bootstrap.log"
Say ''
Say 'Leave this PC switched on and connected: PatchGate now manages it through the Bank A Tactical.'
Say "When the test is over, undo everything:  powershell -ExecutionPolicy Bypass -File $cfgDir\Undo-BankPC.ps1"
if ($failed.Count -gt 0 -or $all.Count -eq 0) { exit 2 }
exit 0
