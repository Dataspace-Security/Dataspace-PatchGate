#Requires -Version 5.1
<#
  PatchGate hosted lab — turns a fresh Windows Sandbox into an OFFLINE "Bank A PC".
  Runs automatically at sandbox logon (LogonCommand in PatchGateLab.wsb). Reads lab.json from the
  read-only mapped folder C:\PatchGateLab\config and writes all evidence to C:\PatchGateLab\out.
  Also run unchanged on a spare physical PC by lab/pc-kit/Start-BankPC.ps1 (backup first, Undo-BankPC.ps1).

  1. trust the lab root CA (the bank's internal CA)
  2. hosts entries for the bank's site services only: Tactical (api/rmm/mesh) + connector cache (pg-cache)
  3. Windows Firewall: block ALL outbound except the lab host on 443 (Tactical) and 8443 (connector cache)
  4. prove isolation: internet unreachable, PatchGate (our server) unreachable, Tactical + cache reachable
  5. pre-install OUTDATED third-party apps (what a real bank PC already has)
  6. install the Tactical agent FROM THE SITE CONNECTOR CACHE (SHA-256 verified) and enroll it
#>
$ErrorActionPreference = 'Stop'
$cfgDir = 'C:\PatchGateLab\config'
$outDir = 'C:\PatchGateLab\out'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
Start-Transcript -Path (Join-Path $outDir 'bootstrap.log') -Force | Out-Null

function Step($n) { Write-Output "==== $n ====" }
function Result($name, $ok, $detail) {
    $line = "{0}`t{1}`t{2}" -f $(if ($ok) { 'PASS' } else { 'FAIL' }), $name, $detail
    Add-Content -Path (Join-Path $outDir 'results.tsv') -Value $line
    Write-Output $line
}

try {
    $cfg = Get-Content (Join-Path $cfgDir 'lab.json') -Raw | ConvertFrom-Json
    $hostIp = $cfg.hostIp

    Step 'Trust lab root CA'
    Import-Certificate -FilePath (Join-Path $cfgDir 'ca.crt') -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
    Result 'ca-trusted' $true 'PatchGate Lab Root CA in LocalMachine\Root'

    Step 'Hosts entries'
    $hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
    # Physical PC (lab/pc-kit): the hosts file may lack a final newline and the kit may run twice.
    $hostsText = [IO.File]::ReadAllText($hostsFile)
    if ($hostsText.Length -gt 0 -and -not $hostsText.EndsWith("`n")) { Add-Content -Path $hostsFile -Value '' }
    foreach ($name in $cfg.hostNames) {
        if ($hostsText -notmatch ('(?m)^' + [regex]::Escape("$hostIp`t$name") + '\s*$')) { Add-Content -Path $hostsFile -Value "$hostIp`t$name" }
    }
    Result 'hosts' $true ($cfg.hostNames -join ', ')

    Step 'Firewall: deny all outbound except the site Tactical + connector cache'
    Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True -DefaultOutboundAction Block -DefaultInboundAction Block
    # Re-run on a physical PC: replace the kit's own rules instead of adding duplicates.
    Get-NetFirewallRule -DisplayName 'PatchGateLab-Allow-*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    New-NetFirewallRule -DisplayName 'PatchGateLab-Allow-LabHost' -Direction Outbound -Action Allow `
        -RemoteAddress $hostIp -Protocol TCP -RemotePort ($cfg.allowedPorts) | Out-Null
    New-NetFirewallRule -DisplayName 'PatchGateLab-Allow-Loopback' -Direction Outbound -Action Allow -RemoteAddress 127.0.0.1 | Out-Null
    Result 'firewall' $true "outbound allowed only to ${hostIp}:$($cfg.allowedPorts -join ',')"

    Step 'Prove isolation'
    foreach ($target in @('github.com', 'www.microsoft.com', '8.8.8.8')) {
        $reach = Test-NetConnection -ComputerName $target -Port 443 -WarningAction SilentlyContinue -InformationLevel Quiet
        Result "internet-blocked:$target" (-not $reach) $(if ($reach) { 'REACHABLE - isolation broken' } else { 'unreachable (expected)' })
    }
    # A bank PC never talks to PatchGate (our server): only the site connector does, outbound.
    $pgTcp = Test-NetConnection -ComputerName $hostIp -Port 3443 -WarningAction SilentlyContinue -InformationLevel Quiet
    Result "patchgate-blocked:${hostIp}:3443" (-not $pgTcp) $(if ($pgTcp) { 'REACHABLE - PC can reach PatchGate' } else { 'unreachable (expected)' })
    foreach ($u in $cfg.patchgateUrls) {
        try { $r = Invoke-WebRequest -UseBasicParsing -Uri $u -TimeoutSec 15; Result "patchgate-blocked:$u" $false "HTTP $($r.StatusCode) - PC can reach PatchGate" }
        catch { Result "patchgate-blocked:$u" $true "unreachable (expected): $($_.Exception.Message)" }
    }
    foreach ($u in @($cfg.tacticalHealthUrl, $cfg.cacheHealthUrl)) {
        try { $r = Invoke-WebRequest -UseBasicParsing -Uri $u -TimeoutSec 20; Result "site-reachable:$u" $true "HTTP $($r.StatusCode)" }
        catch { Result "site-reachable:$u" $false $_.Exception.Message }
    }

    Step 'Pre-existing OUTDATED software (what a real bank PC already has)'
    $fixturesFile = Join-Path $cfgDir 'fixtures.json'
    if (Test-Path $fixturesFile) {
        foreach ($fx in (Get-Content $fixturesFile -Raw | ConvertFrom-Json)) {
            $f = Join-Path $cfgDir ("fixtures\" + $fx.name)
            $sha = (Get-FileHash -Algorithm SHA256 -LiteralPath $f).Hash.ToLowerInvariant()
            if ($sha -ne $fx.sha256) { Result "fixture:$($fx.id)" $false 'hash mismatch'; continue }
            if ($fx.kind -eq 'msi') {
                $p = Start-Process "$env:SystemRoot\System32\msiexec.exe" -ArgumentList @('/i', "`"$f`"", '/qn', '/norestart') -Wait -PassThru
            } else {
                $p = Start-Process -FilePath $f -ArgumentList @($fx.switches -split '\s+' | Where-Object { $_ }) -Wait -PassThru
            }
            Result "fixture:$($fx.id)" (@(0, 3010, 1641) -contains $p.ExitCode) "old $($fx.version) via $($fx.installerType), exit $($p.ExitCode)"
        }
    }

    Step "Install Tactical agent $($cfg.agentVersion) from the site connector cache"
    $exe = Join-Path $env:TEMP 'tacticalagent.exe'
    Invoke-WebRequest -UseBasicParsing -Uri $cfg.agentUrl -OutFile $exe
    $sha = (Get-FileHash -Algorithm SHA256 -LiteralPath $exe).Hash.ToLowerInvariant()
    Result 'agent-sha256' ($sha -eq $cfg.agentSha256) "got $sha"
    if ($sha -ne $cfg.agentSha256) { throw 'agent hash mismatch — refusing to install' }

    $p = Start-Process -FilePath $exe -ArgumentList '/VERYSILENT', '/SUPPRESSMSGBOXES' -Wait -PassThru
    Result 'agent-inno-install' ($p.ExitCode -eq 0) "exit $($p.ExitCode)"

    $agentBin = 'C:\Program Files\TacticalAgent\tacticalrmm.exe'
    $args = @('-m', 'install', '--api', $cfg.tacticalApiUrl, '--client-id', "$($cfg.clientId)", '--site-id', "$($cfg.siteId)",
        '--agent-type', 'workstation', '--auth', $cfg.installToken, '--nomesh', '--silent')
    $p = Start-Process -FilePath $agentBin -ArgumentList $args -Wait -PassThru
    Result 'agent-enroll' ($p.ExitCode -eq 0) "exit $($p.ExitCode)"

    Start-Sleep -Seconds 20
    $svc = Get-Service -Name tacticalrmm -ErrorAction SilentlyContinue
    Result 'agent-service' ($svc -and $svc.Status -eq 'Running') "$($svc.Status)"
}
catch {
    Result 'bootstrap' $false $_.Exception.Message
}
finally {
    Stop-Transcript | Out-Null
    New-Item -ItemType File -Path (Join-Path $outDir 'DONE') -Force | Out-Null
}
