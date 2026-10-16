#Requires -Version 5.1
<#
  PatchGate lab - undo what Start-BankPC.ps1 / bootstrap.ps1 changed on a spare PC. Elevated PowerShell:

      powershell -ExecutionPolicy Bypass -File C:\PatchGateLab\config\Undo-BankPC.ps1
      powershell -ExecutionPolicy Bypass -File C:\PatchGateLab\config\Undo-BankPC.ps1 -WhatIf   (dry run: show, change nothing)

  Uses the backup in C:\PatchGateLab\backup (taken by Start-BankPC.ps1 BEFORE any change):
    1. Tactical agent: its own uninstaller, silent (skipped if an agent was already there before the kit)
    2. firewall rules named "PatchGateLab-*" (only the kit creates these): removed
    3. firewall profiles: Enabled + default inbound/outbound action restored per profile
    4. hosts file: restored from the backup; if it was edited since, only the kit's lines are removed
    5. lab CA: removed from LocalMachine\Root by thumbprint (skipped if it was trusted before the kit)
    6. Defender exclusions the agent install added (TacticalAgent / TacticalRMM paths not in the backup)
  Safe to run twice: every step checks the current state first; a completed undo renames the backup to
  backup-undone-<time> so it is never applied again. Never touches anything the kit did not create.
  NOT undone: the outdated test apps (Firefox, PuTTY, ...) - remove them in Settings > Apps if wanted -
  and the PC's entry in the Bank A Tactical (delete it there).
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Root = 'C:\PatchGateLab',
    [string]$HostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"   # override only for testing
)
$ErrorActionPreference = 'Stop'
$cmdlet = $PSCmdlet

$backupDir = Join-Path $Root 'backup'
$backupFile = Join-Path $backupDir 'backup.json'
$agentDir = 'C:\Program Files\TacticalAgent'
$dry = [bool]$WhatIfPreference
$report = New-Object System.Collections.Generic.List[object]
$errors = 0

function Note($step, $status, $detail) {
    $report.Add([pscustomobject]@{ Step = $step; Status = $status; Detail = $detail })
    $color = switch ($status) { 'ERROR' { 'Red' } 'WOULD' { 'Yellow' } default { 'Gray' } }
    Write-Host ("{0,-10} {1,-9} {2}" -f $step, $status, $detail) -ForegroundColor $color
}
function Act($target, $action) { # true = really do it; false = dry run (prints "What if")
    return $cmdlet.ShouldProcess($target, $action)
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin -and -not $dry) {
    Write-Host 'Run PowerShell as Administrator (or add -WhatIf for a dry run).' -ForegroundColor Red
    exit 1
}
Write-Host ("==== PatchGate lab: undo bank-PC changes{0} ====" -f $(if ($dry) { ' (DRY RUN - nothing is changed)' } else { '' }))

# ------------------------------------------------------------------ inputs: backup + lab.json
$backup = $null
if (Test-Path $backupFile) {
    $backup = Get-Content $backupFile -Raw | ConvertFrom-Json
    Write-Host "Backup: $backupFile (taken $($backup.createdAt) on $($backup.computerName))"
} else {
    Write-Host "No active backup in $backupDir (never started, or already undone). Doing the safe, state-based steps only."
}
$labJson = @((Join-Path $Root 'config\lab.json'), (Join-Path $PSScriptRoot 'config\lab.json'), (Join-Path $PSScriptRoot 'lab.json')) |
    Where-Object { Test-Path $_ } | Select-Object -First 1
$cfg = if ($labJson) { Get-Content $labJson -Raw | ConvertFrom-Json } else { $null }
$hostIp = if ($backup) { $backup.hostIp } elseif ($cfg) { $cfg.hostIp } else { $null }
$hostNames = if ($backup) { @($backup.hostNames) } elseif ($cfg) { @($cfg.hostNames) } else { @() }

# ------------------------------------------------------------------ 1. Tactical agent
$uninstaller = Join-Path $agentDir 'unins000.exe'
if ($backup -and $backup.agentPreExisting) {
    Note 'agent' 'SKIP' 'a Tactical agent was installed BEFORE the kit - left alone'
} elseif (Test-Path $uninstaller) {
    if (Act $uninstaller 'Uninstall the Tactical agent (silent)') {
        try {
            $p = Start-Process -FilePath $uninstaller -ArgumentList '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART' -Wait -PassThru
            Start-Sleep -Seconds 5
            $left = Get-Service -Name tacticalrmm -ErrorAction SilentlyContinue
            if ($p.ExitCode -eq 0 -and -not $left) { Note 'agent' 'DONE' 'Tactical agent uninstalled (also delete this PC in the Bank A Tactical)' }
            else { Note 'agent' 'ERROR' "uninstaller exit $($p.ExitCode); service still present: $([bool]$left)"; $errors++ }
        } catch { Note 'agent' 'ERROR' $_.Exception.Message; $errors++ }
    } else { Note 'agent' 'WOULD' "run $uninstaller /VERYSILENT /SUPPRESSMSGBOXES /NORESTART" }
} else {
    Note 'agent' 'OK' 'no Tactical agent installed'
}

# ------------------------------------------------------------------ 2. PatchGateLab-* firewall rules
$rules = @(Get-NetFirewallRule -DisplayName 'PatchGateLab-*' -ErrorAction SilentlyContinue)
if ($rules.Count -eq 0) {
    Note 'fw-rules' 'OK' 'no PatchGateLab-* firewall rules'
} else {
    foreach ($r in $rules) {
        if (Act "firewall rule $($r.DisplayName)" 'Remove') {
            try { $r | Remove-NetFirewallRule; Note 'fw-rules' 'DONE' "removed $($r.DisplayName)" }
            catch { Note 'fw-rules' 'ERROR' $_.Exception.Message; $errors++ }
        } else { Note 'fw-rules' 'WOULD' "remove $($r.DisplayName) ($($r.Direction) $($r.Action))" }
    }
}

# ------------------------------------------------------------------ 3. firewall profile defaults
if (-not $backup) {
    Note 'fw-profile' 'SKIP' 'no backup - profile settings left as they are'
} else {
    $current = @{}
    Get-NetFirewallProfile -PolicyStore PersistentStore | ForEach-Object { $current["$($_.Name)"] = $_ }
    foreach ($b in @($backup.firewallProfiles)) {
        $c = $current["$($b.Name)"]
        $now = "Enabled=$($c.Enabled) In=$($c.DefaultInboundAction) Out=$($c.DefaultOutboundAction)"
        $want = "Enabled=$($b.Enabled) In=$($b.DefaultInboundAction) Out=$($b.DefaultOutboundAction)"
        if ($c -and $now -eq $want) { Note 'fw-profile' 'OK' "$($b.Name): already $want"; continue }
        if (Act "firewall profile $($b.Name)" "Restore $want (now $now)") {
            try {
                Set-NetFirewallProfile -PolicyStore PersistentStore -Name $b.Name -Enabled $b.Enabled `
                    -DefaultInboundAction $b.DefaultInboundAction -DefaultOutboundAction $b.DefaultOutboundAction
                Note 'fw-profile' 'DONE' "$($b.Name): $now -> $want"
            } catch { Note 'fw-profile' 'ERROR' "$($b.Name): $($_.Exception.Message)"; $errors++ }
        } else { Note 'fw-profile' 'WOULD' "$($b.Name): $now -> $want" }
    }
}

# ------------------------------------------------------------------ 4. hosts file
function Test-KitLine($line) {
    if (-not $hostIp) { return $false }
    $parts = @(($line.Trim() -split '\s+') | Where-Object { $_ })
    return ($parts.Count -eq 2 -and $parts[0] -eq $hostIp -and $hostNames -contains $parts[1])
}
$hostsNow = [IO.File]::ReadAllText($hostsFile)
$kitLines = @(($hostsNow -split "`r?`n") | Where-Object { Test-KitLine $_ })
$hostsBak = if ($backup) { Join-Path $backupDir $backup.hostsFile } else { $null }
if ($hostsBak -and (Test-Path $hostsBak)) {
    $bakText = [IO.File]::ReadAllText($hostsBak)
    $nowWithoutKit = (($hostsNow -split "`r?`n") | Where-Object { -not (Test-KitLine $_) }) -join "`n"
    $bakNorm = (($bakText -split "`r?`n") | Where-Object { -not (Test-KitLine $_) }) -join "`n"
    if ($hostsNow -eq $bakText) {
        Note 'hosts' 'OK' 'already identical to the backup'
    } elseif ($nowWithoutKit.TrimEnd() -eq $bakNorm.TrimEnd()) {
        if (Act $hostsFile 'Restore from backup') {
            try { Copy-Item -LiteralPath $hostsBak -Destination $hostsFile -Force; Note 'hosts' 'DONE' "restored from backup (removed: $($kitLines -join '; '))" }
            catch { Note 'hosts' 'ERROR' $_.Exception.Message; $errors++ }
        } else { Note 'hosts' 'WOULD' "restore from backup (removes: $($kitLines -join '; '))" }
    } else {
        # Edited by someone else since the backup: do not throw their change away, remove only our lines.
        if ($kitLines.Count -eq 0) { Note 'hosts' 'OK' 'changed since the backup, but contains no kit lines - left alone' }
        elseif (Act $hostsFile 'Remove only the kit lines (file was edited since the backup)') {
            try {
                $kept = ($hostsNow -split "`r?`n") | Where-Object { -not (Test-KitLine $_) }
                Set-Content -Path $hostsFile -Value $kept -Encoding ASCII
                Note 'hosts' 'DONE' "edited since backup: removed only $($kitLines -join '; ')"
            } catch { Note 'hosts' 'ERROR' $_.Exception.Message; $errors++ }
        } else { Note 'hosts' 'WOULD' "file edited since backup: remove only $($kitLines -join '; ')" }
    }
} elseif ($kitLines.Count -gt 0) {
    if (Act $hostsFile 'Remove the kit lines (no backup)') {
        try {
            $kept = ($hostsNow -split "`r?`n") | Where-Object { -not (Test-KitLine $_) }
            Set-Content -Path $hostsFile -Value $kept -Encoding ASCII
            Note 'hosts' 'DONE' "removed $($kitLines -join '; ')"
        } catch { Note 'hosts' 'ERROR' $_.Exception.Message; $errors++ }
    } else { Note 'hosts' 'WOULD' "remove $($kitLines -join '; ')" }
} else {
    Note 'hosts' 'OK' 'no kit lines in the hosts file'
}

# ------------------------------------------------------------------ 5. lab CA
$thumb = $null
if ($backup) { $thumb = $backup.caThumbprint }
else {
    $caFile = @((Join-Path $Root 'config\ca.crt'), (Join-Path $PSScriptRoot 'config\ca.crt'), (Join-Path $PSScriptRoot 'ca.crt')) |
        Where-Object { Test-Path $_ } | Select-Object -First 1
    if ($caFile) { $thumb = (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($caFile)).Thumbprint }
}
if ($backup -and $backup.caPreExisting) {
    Note 'lab-ca' 'SKIP' "CA $thumb was trusted BEFORE the kit - left alone"
} elseif (-not $thumb) {
    Note 'lab-ca' 'SKIP' 'no backup and no ca.crt found - cannot identify the lab CA'
} elseif (Test-Path "Cert:\LocalMachine\Root\$thumb") {
    if (Act "Cert:\LocalMachine\Root\$thumb" 'Remove the lab CA') {
        try { Remove-Item -LiteralPath "Cert:\LocalMachine\Root\$thumb" -Force; Note 'lab-ca' 'DONE' "removed $thumb from LocalMachine\Root" }
        catch { Note 'lab-ca' 'ERROR' $_.Exception.Message; $errors++ }
    } else { Note 'lab-ca' 'WOULD' "remove $thumb from LocalMachine\Root" }
} else {
    Note 'lab-ca' 'OK' "lab CA $thumb not in LocalMachine\Root"
}

# ------------------------------------------------------------------ 6. Defender exclusions added by the agent install
if ($backup -and $backup.agentPreExisting) {
    Note 'defender' 'SKIP' 'agent pre-existed - exclusions left alone'
} else {
    $before = if ($backup) { @($backup.defenderExclusionPaths) } else { @() }
    $now = @()
    try { $now = @((Get-MpPreference -ErrorAction Stop).ExclusionPath | Where-Object { $_ }) } catch { $now = @() }
    $ours = @($now | Where-Object { ($_ -like '*TacticalAgent*' -or $_ -like '*TacticalRMM*') -and ($before -notcontains $_) })
    if ($ours.Count -eq 0) { Note 'defender' 'OK' 'no Tactical exclusions added by the kit' }
    foreach ($x in $ours) {
        if (Act "Defender exclusion $x" 'Remove') {
            try { Remove-MpPreference -ExclusionPath $x; Note 'defender' 'DONE' "removed exclusion $x" }
            catch { Note 'defender' 'ERROR' $_.Exception.Message; $errors++ }
        } else { Note 'defender' 'WOULD' "remove exclusion $x" }
    }
}

# ------------------------------------------------------------------ finish
Write-Host ''
if ($dry) {
    Write-Host 'DRY RUN finished - nothing was changed. Run again without -WhatIf (as Administrator) to apply.'
    exit 0
}
if ($errors -gt 0) {
    Write-Host "$errors step(s) failed - the backup is kept; fix the cause and run Undo-BankPC.ps1 again." -ForegroundColor Red
    exit 1
}
if ($backup) {
    $done = Join-Path $Root ('backup-undone-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
    Rename-Item -LiteralPath $backupDir -NewName (Split-Path $done -Leaf)
    Write-Host "Backup archived as $done (it will not be applied again)."
}
Write-Host 'Undo complete. The outdated test apps stay installed (Settings > Apps to remove them).'
Write-Host "C:\PatchGateLab still holds the logs; delete it when you no longer need them."
exit 0
