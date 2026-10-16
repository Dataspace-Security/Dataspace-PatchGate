#Requires -Version 5.1
<#
.SYNOPSIS
  Installs the Tactical RMM agent on a bank PC for PatchGate (offline: the PC talks ONLY to its site).

.DESCRIPTION
  1. Exits 0 at once if the agent service is already installed and running (safe to run at every boot).
  2. Trusts the bank / site CA (LocalMachine\Root) if a CA file is given.
  3. Optionally writes hosts entries for the site names (only when the bank has no internal DNS for them).
  4. Downloads the agent from the site's PatchGate package cache (https), or uses the copy next to this
     script, and installs it ONLY if its SHA-256 matches.
  5. Installs silently, enrols it with the site's Tactical (install token), and checks the service runs.
  Log: C:\ProgramData\PatchGate\agent-install.log (the install token is never written to it).
  Exit codes: 0 ok / already installed, 1 bad input, 2 download or SHA-256 failure, 3 install/enrol failure.

.PARAMETER ConfigFile
  patchgate-pc.json written by install-site.sh (in /opt/patchgate-site/pc/). Simplest way: copy that folder
  to a read-only share and pass the JSON path. All other parameters override values from the file.

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
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$LogDir = Join-Path $env:ProgramData 'PatchGate'
$LogFile = Join-Path $LogDir 'agent-install.log'
$ServiceName = 'tacticalrmm'
$AgentExe = 'C:\Program Files\TacticalAgent\tacticalrmm.exe'

function Write-Log([string]$Message, [string]$Level = 'INFO') {
    $line = '{0} [{1}] {2}' -f (Get-Date).ToString('yyyy-MM-ddTHH:mm:ssK'), $Level, $Message
    try { Add-Content -Path $LogFile -Value $line -Encoding UTF8 } catch { }
    Write-Output $line
}
function Stop-Install([int]$Code, [string]$Message) {
    Write-Log $Message 'ERROR'
    exit $Code
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

# ---------------------------------------------------------------- 1. already installed?
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc -and -not $Force) {
    if ($svc.Status -ne 'Running') {
        try { Start-Service -Name $ServiceName; Write-Log 'agent service was stopped: started it' } catch { Write-Log "could not start the agent service: $($_.Exception.Message)" 'WARN' }
    }
    Write-Log "Tactical agent already installed (service $ServiceName = $((Get-Service $ServiceName).Status)). Nothing to do."
    exit 0
}

# ---------------------------------------------------------------- settings (file, then parameters)
$cfg = $null
$baseDir = $null
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

# ---------------------------------------------------------------- 3. hosts entries (only without bank DNS)
if ($SiteIp) {
    if (-not ($SiteIp -as [ipaddress])) { Stop-Install 1 "invalid -SiteIp $SiteIp" }
    $hostsFile = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    $names = @()
    if ($cfg -and $cfg.hostNames) { $names = @($cfg.hostNames) } else { $names = @(([uri]$TacticalApiUrl).Host) }
    $current = Get-Content -LiteralPath $hostsFile -ErrorAction SilentlyContinue
    foreach ($n in $names) {
        if (-not ($current | Where-Object { $_ -match "^\s*[0-9a-fA-F.:]+\s+$([regex]::Escape($n))(\s|$)" })) {
            Add-Content -LiteralPath $hostsFile -Value "$SiteIp`t$n`t# PatchGate site"
            Write-Log "hosts: $n -> $SiteIp"
        }
    }
}

# ---------------------------------------------------------------- 4. agent: site cache, else the local copy; SHA-256 must match
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

# ---------------------------------------------------------------- 5. install + enrol + verify
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
exit 0
