#Requires -Version 5.1
<#
.SYNOPSIS
  Installs the Tactical RMM agent on a bank PC for PatchGate (offline: the PC talks ONLY to its site).

.DESCRIPTION
  0. Locks Windows Update (ALWAYS, also when the agent is already installed): the PC must never take updates
     from Microsoft by itself, only through PatchGate (offline scan with wsusscn2.cab + update files from the
     site cache). Sets the Windows Update group-policy values in $WuLockValues (RUNBOOK "PatchGate locks
     Windows Update"): Windows Update and the Tactical agent's own update scan/install point to a server that
     does not exist, so nothing reaches Microsoft, while the offline scan (WUA scan package service) and
     wusa.exe / DISM installs keep working. wuauserv stays Manual (PatchGate needs it). -SkipWuLock skips it.
  1. Exits 0 at once if the agent service is already installed and running (safe to run at every boot).
  2. Trusts the bank / site CA (LocalMachine\Root) if a CA file is given (caFile in patchgate-pc.json).
  3. Site names (hostNames in patchgate-pc.json, else the Tactical API + cache host) that do NOT resolve via
     DNS get a hosts entry pointing to the site IP (siteIp in patchgate-pc.json or -SiteIp). All missing
     names are written in ONE append, retried when another process (Defender, an editor) holds the file; if
     it still fails the exact lines to add are printed.
  4. Self-test: the PC must reach the site's Tactical API and package cache over HTTPS with a trusted
     certificate, before anything is installed (exit 4 with the reason otherwise).
  5. Downloads the agent from the site's PatchGate package cache (https), or uses the copy next to this
     script, and installs it ONLY if its SHA-256 matches.
  6. Installs silently, enrols it with the site's Tactical (install token), and checks the service runs.
  Ends with one line: "OK - PC enrolled, will appear in PatchGate within minutes" (or "FAILED - <reason>").
  Easiest: double-click Install-PatchGateAgent.cmd in the folder that holds this script + patchgate-pc.json
  (asks for administrator rights, then runs this script with that JSON).
  Log: C:\ProgramData\PatchGate\agent-install.log (the install token is never written to it).
  Exit codes: 0 ok / already installed, 1 bad input, 2 download or SHA-256 failure, 3 install/enrol failure,
  4 the site (Tactical API / package cache) is not reachable from this PC.

.PARAMETER SkipWuLock
  Do not lock Windows Update (NOT recommended: the PC can then take updates from Microsoft by itself and
  PatchGate shows it as "NOT locked").

.PARAMETER BlockDefenderDefinitionUpdates
  Default: Microsoft Defender fetches its definitions (security intelligence, signature data only, never OS
  updates) itself from Microsoft's Malware Protection Center (MMPC), so protection never goes stale.
  With this switch Defender's only source is the locked Windows Update server (no definitions from the
  internet). -AllowDefenderDefinitionUpdates is accepted for compatibility (it is the default).

.PARAMETER AllowDefenderDefinitionUpdates
  Compatibility switch: definitions from MMPC is already the default.

.PARAMETER ConfigFile
  patchgate-pc.json written by install-site.sh (in /opt/patchgate-site/pc/). Simplest way: copy that folder
  to a read-only share and pass the JSON path (default: patchgate-pc.json next to this script). All other
  parameters override values from the file. Optional fields used here: siteIp (IPv4/IPv6 of the site VM),
  hostNames (array of the site names: Tactical API, package cache, ...), caFile (path relative to the JSON).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File \\fs01\patchgate$\Install-PatchGateAgent.ps1 -ConfigFile \\fs01\patchgate$\patchgate-pc.json

.EXAMPLE
  .\Install-PatchGateAgent.ps1 -CacheUrl https://pg-cache.bank.local:8443/repo -TacticalApiUrl https://api.bank.local `
     -InstallToken <token> -ClientId 1 -SiteId 1 -AgentRepoPath tactical/agent/2.11.0/tacticalagent-v2.11.0-windows-amd64.exe `
     -AgentSha256 <64 hex> -CaFile .\bank-ca.pem

.NOTES
  GPO deployment (computer startup script, runs as SYSTEM):
    Computer Configuration > Policies > Windows Settings > Scripts > Startup > PowerShell Scripts:
      Script: \\fs01\patchgate$\Install-PatchGateAgent.ps1   Parameters: -ConfigFile \\fs01\patchgate$\patchgate-pc.json
    Give "Domain Computers" READ on the share (the JSON holds the install token: no other read access).
    Set "Turn on script execution" to "Allow local scripts and remotely signed scripts" or sign the script.
    The install token expires (default 72 h): renew it on the site VM with `install-site.sh --pc-token 720`
    and copy the new patchgate-pc.json to the share. PCs that already run the agent exit immediately.
#>
[CmdletBinding()]
param(
    [string]$ConfigFile,
    [string]$CacheUrl,
    [string]$TacticalApiUrl,
    [string]$InstallToken,
    [int]$ClientId,
    [int]$SiteId,
    [string]$AgentRepoPath,
    [string]$AgentSha256,
    [string]$AgentFile,
    [string]$CaFile,
    [string]$SiteIp,
    [ValidateSet('auto', 'workstation', 'server')][string]$AgentType = 'auto',
    [switch]$WithMesh,
    [switch]$SkipWuLock,
    [switch]$AllowDefenderDefinitionUpdates,
    [switch]$BlockDefenderDefinitionUpdates,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$LogDir = Join-Path $env:ProgramData 'PatchGate'
$LogFile = Join-Path $LogDir 'agent-install.log'
$ServiceName = 'tacticalrmm'
$AgentExe = 'C:\Program Files\TacticalAgent\tacticalrmm.exe'
$PolicyRoot = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows'
$DefenderUpdateKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates'

# BEGIN PatchGate WU lock values (identical block in patchgate-web/scripts/endpoint/Invoke-PatchGateWuScan.ps1)
$WuLockServer = 'http://patchgate-wu-locked.invalid'
$WuLockValues = @(
    @{ Key = 'WindowsUpdate'; Name = 'WUServer'; Type = 'String'; Value = $WuLockServer },
    @{ Key = 'WindowsUpdate'; Name = 'WUStatusServer'; Type = 'String'; Value = $WuLockServer },
    @{ Key = 'WindowsUpdate'; Name = 'DoNotConnectToWindowsUpdateInternetLocations'; Type = 'DWord'; Value = 1 },
    @{ Key = 'WindowsUpdate'; Name = 'DisableDualScan'; Type = 'DWord'; Value = 1 },
    @{ Key = 'WindowsUpdate'; Name = 'SetPolicyDrivenUpdateSourceForFeatureUpdates'; Type = 'DWord'; Value = 1 },
    @{ Key = 'WindowsUpdate'; Name = 'SetPolicyDrivenUpdateSourceForQualityUpdates'; Type = 'DWord'; Value = 1 },
    @{ Key = 'WindowsUpdate'; Name = 'SetPolicyDrivenUpdateSourceForDriverUpdates'; Type = 'DWord'; Value = 1 },
    @{ Key = 'WindowsUpdate'; Name = 'SetPolicyDrivenUpdateSourceForOtherUpdates'; Type = 'DWord'; Value = 1 },
    @{ Key = 'WindowsUpdate'; Name = 'ExcludeWUDriversInQualityUpdate'; Type = 'DWord'; Value = 1 },
    @{ Key = 'WindowsUpdate'; Name = 'SetDisableUXWUAccess'; Type = 'DWord'; Value = 1 },
    @{ Key = 'WindowsUpdate\AU'; Name = 'UseWUServer'; Type = 'DWord'; Value = 1 },
    @{ Key = 'WindowsUpdate\AU'; Name = 'UseUpdateClassPolicySource'; Type = 'DWord'; Value = 1 },
    @{ Key = 'WindowsUpdate\AU'; Name = 'NoAutoUpdate'; Type = 'DWord'; Value = 1 }
)
# END PatchGate WU lock values

function Write-Log([string]$Message, [string]$Level = 'INFO') {
    $line = '{0} [{1}] {2}' -f (Get-Date).ToString('yyyy-MM-ddTHH:mm:ssK'), $Level, $Message
    try { Add-Content -Path $LogFile -Value $line -Encoding UTF8 } catch { }
    Write-Output $line
}
function Stop-Install([int]$Code, [string]$Message) {
    Write-Log $Message 'ERROR'
    Write-Output "FAILED - $Message"
    exit $Code
}
function Test-Resolves([string]$Name) {
    try { return (@([Net.Dns]::GetHostAddresses($Name)).Count -gt 0) } catch { return $false }
}
# Any HTTP answer (also 401/404) proves DNS, routing, port and a trusted TLS certificate; no answer = error text.
function Test-SiteUrl([string]$Url) {
    try {
        $req = [Net.HttpWebRequest]::Create($Url)
        $req.Method = 'GET'
        $req.Timeout = 15000
        $req.AllowAutoRedirect = $false
        $req.GetResponse().Close()
        return $null
    } catch [Net.WebException] {
        if ($_.Exception.Response) { $_.Exception.Response.Close(); return $null }
        $inner = $_.Exception
        while ($inner.InnerException) { $inner = $inner.InnerException }
        return $inner.Message
    } catch {
        return $_.Exception.Message
    }
}
function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Resolve-Relative([string]$Path, [string]$BaseDir) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    if ([IO.Path]::IsPathRooted($Path) -or -not $BaseDir) { return $Path }
    return (Join-Path $BaseDir $Path)
}

function Protect-Dir([string]$Path) {
    # The agent EXE is staged, hashed and run (as SYSTEM) from here: only SYSTEM and Administrators may write,
    # so a standard user cannot swap it between the SHA-256 check and Start-Process. Inherited ProgramData
    # rights (Users: create files/folders) are removed and ownership is taken back from any pre-creator.
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $admins = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $system = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    $acl.SetOwner($admins)
    foreach ($sid in @($system, $admins)) {
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

if (-not (Test-Admin)) {
    Write-Output 'Run as administrator (or as a GPO computer startup script).'
    exit 1
}
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
try { Protect-Dir $LogDir } catch { Write-Output "cannot restrict $LogDir to SYSTEM/Administrators: $($_.Exception.Message)"; exit 1 }
Write-Log "PatchGate agent installer started on $env:COMPUTERNAME (user $env:USERNAME)"

# ---------------------------------------------------------------- 0. lock Windows Update (every run)
function Set-WuLock {
    foreach ($v in $WuLockValues) {
        $key = Join-Path $PolicyRoot $v.Key
        if (-not (Test-Path -LiteralPath $key)) { New-Item -Path $key -Force | Out-Null }
        New-ItemProperty -LiteralPath $key -Name $v.Name -PropertyType $v.Type -Value $v.Value -Force | Out-Null
    }
    # Defender definitions (signature data only): from MMPC by default; -BlockDefenderDefinitionUpdates = locked WU server only.
    $order = if ($BlockDefenderDefinitionUpdates) { 'InternalDefinitionUpdateServer' } else { 'MMPC' }
    if (-not (Test-Path -LiteralPath $DefenderUpdateKey)) { New-Item -Path $DefenderUpdateKey -Force | Out-Null }
    New-ItemProperty -LiteralPath $DefenderUpdateKey -Name 'FallbackOrder' -PropertyType String -Value $order -Force | Out-Null
    # PatchGate's offline scan and wusa.exe need the Windows Update service: Manual (on demand), never Disabled.
    $wu = Get-CimInstance -ClassName Win32_Service -Filter "Name='wuauserv'" -ErrorAction SilentlyContinue
    if ($wu -and $wu.StartMode -eq 'Disabled') {
        Set-Service -Name wuauserv -StartupType Manual
        Write-Log 'wuauserv was Disabled: set to Manual (PatchGate needs it for the offline scan and installs)'
    }
    # Restart so the service reads the new policy now (failure is harmless: it reads it on its next start).
    try { Restart-Service -Name wuauserv -Force -ErrorAction Stop } catch { }
    Write-Log "Windows Update locked: updates only through PatchGate (WU server $WuLockServer, NoAutoUpdate=1, Defender definitions: $order)"
}
if ($SkipWuLock) {
    Write-Log 'Windows Update lock SKIPPED (-SkipWuLock): this PC can still take updates from Microsoft by itself' 'WARN'
} else {
    try { Set-WuLock } catch { Stop-Install 3 "could not lock Windows Update: $($_.Exception.Message)" }
}

# ---------------------------------------------------------------- 1. already installed?
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc -and -not $Force) {
    if ($svc.Status -ne 'Running') {
        try { Start-Service -Name $ServiceName; Write-Log 'agent service was stopped: started it' } catch { Write-Log "could not start the agent service: $($_.Exception.Message)" 'WARN' }
    }
    Write-Log "Tactical agent already installed (service $ServiceName = $((Get-Service $ServiceName).Status)). Nothing to do."
    Write-Output 'OK - agent already installed on this PC (Windows Update lock re-applied)'
    exit 0
}

# ---------------------------------------------------------------- settings (file, then parameters)
$cfg = $null
$baseDir = $null
if (-not $ConfigFile -and $PSScriptRoot) {
    $nextToScript = Join-Path $PSScriptRoot 'patchgate-pc.json'
    if (Test-Path -LiteralPath $nextToScript) { $ConfigFile = $nextToScript }
}
if ($ConfigFile) {
    if (-not (Test-Path -LiteralPath $ConfigFile)) { Stop-Install 1 "config file not found: $ConfigFile" }
    $cfg = Get-Content -LiteralPath $ConfigFile -Raw | ConvertFrom-Json
    $baseDir = Split-Path -Parent (Resolve-Path -LiteralPath $ConfigFile).ProviderPath
}
function Pick($param, $fromFile) { if ($param) { return $param } return $fromFile }
$is64 = [Environment]::Is64BitOperatingSystem
$CacheUrl = Pick $CacheUrl $cfg.cacheUrl
$TacticalApiUrl = Pick $TacticalApiUrl $cfg.tacticalApiUrl
$InstallToken = Pick $InstallToken $cfg.installToken
if (-not $ClientId -and $cfg) { $ClientId = [int]$cfg.clientId }
if (-not $SiteId -and $cfg) { $SiteId = [int]$cfg.siteId }
if ($is64) {
    $AgentRepoPath = Pick $AgentRepoPath $cfg.agentRepoPath
    $AgentSha256 = Pick $AgentSha256 $cfg.agentSha256
} else {
    $AgentRepoPath = Pick $AgentRepoPath $cfg.agentRepoPath386
    $AgentSha256 = Pick $AgentSha256 $cfg.agentSha256_386
}
$CaFile = Resolve-Relative (Pick $CaFile $cfg.caFile) $baseDir
$SiteIp = Pick $SiteIp $cfg.siteIp
if (-not $AgentFile -and $AgentRepoPath -and $baseDir) { $AgentFile = Join-Path $baseDir (Split-Path -Leaf $AgentRepoPath) }

foreach ($pair in @(@('TacticalApiUrl', $TacticalApiUrl), @('InstallToken', $InstallToken), @('AgentSha256', $AgentSha256))) {
    if ([string]::IsNullOrWhiteSpace($pair[1])) { Stop-Install 1 "missing $($pair[0]) (pass -ConfigFile or -$($pair[0]))" }
}
if ($ClientId -le 0 -or $SiteId -le 0) { Stop-Install 1 'missing -ClientId / -SiteId' }
if ($TacticalApiUrl -notmatch '^https://[A-Za-z0-9.-]+(:\d+)?/?$') { Stop-Install 1 "TacticalApiUrl must be https://host: $TacticalApiUrl" }
$AgentSha256 = $AgentSha256.ToLowerInvariant()
if ($AgentSha256 -notmatch '^[a-f0-9]{64}$') { Stop-Install 1 'AgentSha256 must be 64 hex digits' }
if ($cfg -and $cfg.installTokenExpiresAt) {
    $exp = [DateTimeOffset]::Parse($cfg.installTokenExpiresAt)
    if ($exp -lt [DateTimeOffset]::UtcNow) { Stop-Install 1 "the install token expired at ${exp}: run 'install-site.sh --pc-token' on the site VM and copy the new patchgate-pc.json" }
}

# ---------------------------------------------------------------- 2. trust the bank / site CA
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
if ($CaFile) {
    if (-not (Test-Path -LiteralPath $CaFile)) { Stop-Install 1 "CA file not found: $CaFile" }
    $ca = New-Object Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (Resolve-Path -LiteralPath $CaFile).ProviderPath
    if (Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Thumbprint -eq $ca.Thumbprint }) {
        Write-Log "bank CA already trusted ($($ca.Subject))"
    } else {
        Import-Certificate -FilePath (Resolve-Path -LiteralPath $CaFile).ProviderPath -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
        Write-Log "trusted the bank CA $($ca.Subject) (thumbprint $($ca.Thumbprint))"
    }
}

# ---------------------------------------------------------------- 3. hosts entries (only for names DNS does not resolve)
$siteNames = @()
if ($cfg -and $cfg.hostNames) { $siteNames = @($cfg.hostNames | ForEach-Object { [string]$_ }) }
else {
    $siteNames = @(([uri]$TacticalApiUrl).Host)
    if ($CacheUrl) { $siteNames += ([uri]$CacheUrl).Host }
}
$siteNames = @($siteNames | Where-Object { $_ -and -not ($_ -as [ipaddress]) } | Select-Object -Unique)
foreach ($n in $siteNames) {
    if ($n -notmatch '^[A-Za-z0-9]([A-Za-z0-9-]{0,62})(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}))*$') { Stop-Install 1 "invalid host name in hostNames: $n" }
}
$unresolvedNames = @($siteNames | Where-Object { -not (Test-Resolves $_) })
if ($unresolvedNames.Count -gt 0 -and -not $SiteIp) {
    Stop-Install 1 "$($unresolvedNames -join ', ') do not resolve: the bank's DNS has no entry and no siteIp is given (siteIp in patchgate-pc.json or -SiteIp)"
}
if ($unresolvedNames.Count -gt 0) {
    if (-not ($SiteIp -as [ipaddress])) { Stop-Install 1 "invalid site IP $SiteIp" }
    $hostsFile = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    $current = @(Get-Content -LiteralPath $hostsFile -ErrorAction SilentlyContinue)
    $missing = @()
    foreach ($n in $unresolvedNames) {
        if (-not ($current | Where-Object { $_ -match "^\s*[0-9a-fA-F.:]+\s+$([regex]::Escape($n))(\s|$)" })) { $missing += $n }
    }
    if ($missing.Count -gt 0) {
        $lines = @($missing | ForEach-Object { "$SiteIp`t$_`t# PatchGate site" })
        $raw = ''
        try { $raw = [IO.File]::ReadAllText($hostsFile) } catch { }
        $block = ($lines -join "`r`n") + "`r`n"
        if ($raw.Length -gt 0 -and -not $raw.EndsWith("`n")) { $block = "`r`n" + $block }
        # ONE append for all names. Defender / an editor may hold the file for a moment: retry with back-off.
        $written = $false
        $lastError = ''
        for ($i = 1; $i -le 10 -and -not $written; $i++) {
            try {
                [IO.File]::AppendAllText($hostsFile, $block, [Text.Encoding]::ASCII)
                $written = $true
            } catch {
                $lastError = $_.Exception.Message
                Start-Sleep -Milliseconds (300 * $i)
            }
        }
        if ($written) {
            foreach ($n in $missing) { Write-Log "hosts: $n -> $SiteIp" }
        } else {
            Write-Log "could not write $hostsFile after 10 tries ($lastError). Add these lines to it manually:" 'WARN'
            foreach ($l in $lines) { Write-Log "    $l" 'WARN' }
            $unresolved = @()
            foreach ($n in $missing) {
                try { [void][Net.Dns]::GetHostAddresses($n) } catch { $unresolved += $n }
            }
            if ($unresolved.Count -gt 0) {
                Stop-Install 1 "hosts file not updated and $($unresolved -join ', ') do not resolve: add the lines above to $hostsFile and run again"
            }
            Write-Log 'the names already resolve (bank DNS / earlier entries): continuing without the new hosts entries' 'WARN'
        }
    }
}

# ---------------------------------------------------------------- 4. self-test: the PC reaches its site (DNS, port, trusted TLS)
$checks = @(@('Tactical API', ($TacticalApiUrl.TrimEnd('/') + '/')))
if ($CacheUrl) { $checks += , @('package cache', ($CacheUrl.TrimEnd('/') + '/')) }
foreach ($c in $checks) {
    $problem = Test-SiteUrl $c[1]
    if ($problem) { Stop-Install 4 "this PC cannot reach the site $($c[0]) $($c[1]): $problem (network / firewall to the site VM on 443, bank CA trusted?)" }
    Write-Log "self-test: $($c[0]) $($c[1]) reachable"
}

# ---------------------------------------------------------------- 5. agent: site cache, else the local copy; SHA-256 must match
$dest = Join-Path $LogDir ('tacticalagent-' + [guid]::NewGuid().ToString('N') + '.exe')
$got = $false
if ($CacheUrl -and $AgentRepoPath) {
    $url = $CacheUrl.TrimEnd('/') + '/' + $AgentRepoPath.TrimStart('/')
    try {
        Write-Log "downloading the agent from the site cache: $url"
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $dest -TimeoutSec 600
        $got = $true
    } catch {
        Write-Log "site cache download failed: $($_.Exception.Message)" 'WARN'
    }
}
if (-not $got) {
    if ($AgentFile -and (Test-Path -LiteralPath $AgentFile)) {
        Write-Log "using the agent copy next to the script: $AgentFile"
        Copy-Item -LiteralPath $AgentFile -Destination $dest -Force
    } else {
        Stop-Install 2 'agent not available: not in the site cache yet (ask PatchGate to cache it for this site) and no local copy found'
    }
}
$sha = (Get-FileHash -Algorithm SHA256 -LiteralPath $dest).Hash.ToLowerInvariant()
if ($sha -ne $AgentSha256) {
    Remove-Item -LiteralPath $dest -Force -ErrorAction SilentlyContinue
    Stop-Install 2 "agent SHA-256 mismatch (got $sha, expected $AgentSha256): NOT installed"
}
Write-Log "agent SHA-256 verified ($sha)"

# ---------------------------------------------------------------- 6. install + enrol + verify
try {
    $p = Start-Process -FilePath $dest -ArgumentList '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART' -Wait -PassThru
    if ($p.ExitCode -ne 0) { Stop-Install 3 "agent setup failed (exit $($p.ExitCode))" }
    Write-Log 'agent files installed'
    if (-not (Test-Path -LiteralPath $AgentExe)) { Stop-Install 3 "$AgentExe not found after setup" }

    if ($AgentType -eq 'auto') {
        $productType = (Get-CimInstance -ClassName Win32_OperatingSystem).ProductType
        $AgentType = if ($productType -eq 1) { 'workstation' } else { 'server' }
    }
    $enrolArgs = @('-m', 'install', '--api', $TacticalApiUrl.TrimEnd('/'), '--client-id', "$ClientId", '--site-id', "$SiteId",
        '--agent-type', $AgentType, '--auth', $InstallToken, '--silent')
    if (-not $WithMesh) { $enrolArgs += '--nomesh' }
    Write-Log "enrolling with $TacticalApiUrl (client $ClientId, site $SiteId, $AgentType)"
    $p = Start-Process -FilePath $AgentExe -ArgumentList $enrolArgs -Wait -PassThru
    if ($p.ExitCode -ne 0) { Stop-Install 3 "enrolment failed (exit $($p.ExitCode)): token valid? PC can reach $TacticalApiUrl on 443?" }
} finally {
    Remove-Item -LiteralPath $dest -Force -ErrorAction SilentlyContinue
}

$deadline = (Get-Date).AddSeconds(90)
do {
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq 'Running') { break }
    Start-Sleep -Seconds 5
} while ((Get-Date) -lt $deadline)
if (-not $svc -or $svc.Status -ne 'Running') { Stop-Install 3 "agent service $ServiceName is not running after enrolment" }
Write-Log "done: agent service $ServiceName is running. The PC appears in PatchGate after the next agent sync."
Write-Output 'OK - PC enrolled, will appear in PatchGate within minutes'
exit 0
