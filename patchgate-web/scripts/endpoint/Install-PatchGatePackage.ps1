#Requires -Version 5.1
<#
.SYNOPSIS
  PatchGate package installer. Runs on offline bank PCs as SYSTEM via Tactical RMM.

.DESCRIPTION
  Register this script ONCE in Tactical (shell: PowerShell), code-sign it with the bank's signing
  certificate, and put its Tactical script id in PatchGate's TACTICAL_INSTALL_SCRIPT_ID.

  Inputs come ONLY from environment variables set by PatchGate (never from args, because Tactical
  joins args into a command line):
    PG_KIND       msi | exe | agent
    PG_REPO_URL   https://patchgate.bank.local/repo   (internal PatchGate repo — never the internet)
    PG_PATH       pkgs/<app>/<version>/<file>.msi|.exe   or   tactical/agent/<ver>/tacticalagent-v<ver>-windows-<arch>.exe
    PG_SHA256     64 lowercase hex
    PG_APP_ID     winget id (Tactical.Agent for agent upgrades)
    PG_VERSION    version string
    PG_PUBLISHER  msi/exe: pinned signer organisation, EXACT match: "O=Google LLC" (empty for agent)
    PG_ARGS       exe only: silent switches; EVERY token must be in $AllowedSwitches below

  Trust per kind:
    msi   — SHA-256 + Authenticode Valid + exact O= pin; msiexec /i /qn /norestart
    exe   — SHA-256 + Authenticode Valid + exact O= pin; allow-listed switches only, no shell
    agent — SHA-256 pinned by an admin-approved PatchGate mirror (public Tactical builds are
            unsigned). Runs via a one-time SYSTEM scheduled task (~30 s later) because the upgrade
            restarts the Tactical agent running this script. The task RE-VERIFIES the SHA-256
            immediately before executing, then deletes the file and itself.

  Working files live in a per-run folder created atomically with an ACL of SYSTEM + Administrators
  only. If the parent folder exists with any other owner/ACE (e.g. pre-created by a local user),
  it is moved aside and recreated, so no local user can swap a verified file before it runs.

  Prints exactly one line "PATCHGATE_RESULT=OK" or "PATCHGATE_RESULT=FAIL:<reason>".
#>

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# MUST match src/lib/thirdparty/switches.ts (case-sensitive; a unit test enforces this).
$AllowedSwitches = @(
    '/S', '/s',
    '/SP-', '/VERYSILENT', '/SILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/ALLUSERS', '/NOCANCEL',
    '/quiet', '/qn', '/passive', '/norestart', '/install',
    '-s', '-q', '--silent', '--quiet', '--norestart'
)
$InstallTimeoutMs = 840000   # stay below the 900 s Tactical script timeout
$SidSystem = 'S-1-5-18'
$SidAdmins = 'S-1-5-32-544'

function Write-Result([string]$Result) {
    Write-Output ("PATCHGATE_RESULT=" + ($Result -replace '[\r\n]', ' '))
}

# ASCII-only patterns anchored with \A ... \z (no Unicode digits, no trailing-newline match).
function Assert-Match([string]$Name, [string]$Value, [string]$Pattern) {
    if ([string]::IsNullOrEmpty($Value) -or -not [regex]::IsMatch($Value, "\A(?:$Pattern)\z", 'CultureInvariant')) {
        throw "invalid $Name"
    }
}

function New-SecureDirectorySecurity {
    $sec = New-Object System.Security.AccessControl.DirectorySecurity
    $sec.SetAccessRuleProtection($true, $false)   # no inheritance
    foreach ($sid in @($SidSystem, $SidAdmins)) {
        $id = New-Object System.Security.Principal.SecurityIdentifier($sid)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($id, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $sec.AddAccessRule($rule)
    }
    $sec.SetOwner((New-Object System.Security.Principal.SecurityIdentifier($SidAdmins)))
    return $sec
}

function Test-TrustedAcl([string]$Path) {
    $acl = Get-Acl -LiteralPath $Path
    $owner = (New-Object System.Security.Principal.NTAccount($acl.Owner)).Translate([System.Security.Principal.SecurityIdentifier]).Value
    if (@($SidSystem, $SidAdmins) -notcontains $owner) { return $false }
    foreach ($ace in $acl.Access) {
        $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
        if (@($SidSystem, $SidAdmins) -notcontains $sid) { return $false }
    }
    return $true
}

# Returns a fresh per-run directory that only SYSTEM/Administrators can touch.
function Get-SecureRunDirectory {
    $root = Join-Path $env:ProgramData 'PatchGate'
    if ((Test-Path -LiteralPath $root) -and -not (Test-TrustedAcl $root)) {
        $aside = "$root.untrusted-" + [guid]::NewGuid().ToString('N')
        Rename-Item -LiteralPath $root -NewName (Split-Path $aside -Leaf)
    }
    if (-not (Test-Path -LiteralPath $root)) {
        [void][System.IO.Directory]::CreateDirectory($root, (New-SecureDirectorySecurity))
    }
    if (-not (Test-TrustedAcl $root)) { throw 'PatchGate folder ACL is not trusted' }
    $run = Join-Path $root ('run-' + [guid]::NewGuid().ToString('N'))
    [void][System.IO.Directory]::CreateDirectory($run, (New-SecureDirectorySecurity))
    if (-not (Test-TrustedAcl $run)) { throw 'run folder ACL is not trusted' }
    return $run
}

function Assert-Publisher($Sig, [string]$Publisher) {
    if ($Sig.Status -ne 'Valid') { throw ("signature " + $Sig.Status) }
    # Exact organisation match on the decoded RDNs (never a substring of the subject string).
    # $Publisher may list up to 4 pins separated by ';' (vendor renamed its signing organisation).
    $expectedOrgs = @($Publisher -split ';' | ForEach-Object { $_.Trim().Substring(2).Trim() })
    $rdns = $Sig.SignerCertificate.SubjectName.Decode(
        [System.Security.Cryptography.X509Certificates.X500DistinguishedNameFlags]::UseNewLines) -split "`r?`n"
    $orgs = $rdns | Where-Object { $_ -like 'O=*' } | ForEach-Object { $_.Substring(2).Trim().Trim('"') }
    $hit = $orgs | Where-Object { $o = $_; $expectedOrgs | Where-Object { $_ -ieq $o } }
    if (-not $hit) { throw 'publisher mismatch' }
}

function Wait-Installer($Proc) {
    # Wait for the installer process itself (not its long-lived children), with a hard timeout.
    if (-not $Proc.WaitForExit($InstallTimeoutMs)) {
        try { $Proc.Kill() } catch { }
        throw 'installer timed out'
    }
    return $Proc.ExitCode
}

$runDir = $null
$keepRunDir = $false
try {
    $kind = $env:PG_KIND
    $repo = $env:PG_REPO_URL
    $path = $env:PG_PATH
    $sha = $env:PG_SHA256
    $appId = $env:PG_APP_ID
    $version = $env:PG_VERSION
    $publisher = $env:PG_PUBLISHER
    $argString = $env:PG_ARGS

    Assert-Match 'PG_KIND' $kind 'msi|exe|agent'
    Assert-Match 'PG_REPO_URL' $repo 'https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._-]+)*'
    Assert-Match 'PG_SHA256' $sha '[a-f0-9]{64}'
    Assert-Match 'PG_APP_ID' $appId '[A-Za-z0-9][A-Za-z0-9.+_-]{2,127}'
    Assert-Match 'PG_VERSION' $version '[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}'
    switch ($kind) {
        'msi'   { Assert-Match 'PG_PATH' $path 'pkgs(/[A-Za-z0-9._-]+)+\.msi' }
        'exe'   { Assert-Match 'PG_PATH' $path 'pkgs(/[A-Za-z0-9._-]+)+\.exe' }
        'agent' {
            Assert-Match 'PG_PATH' $path 'tactical/agent/[0-9]+\.[0-9]+\.[0-9]+/tacticalagent-v[0-9]+\.[0-9]+\.[0-9]+-windows-(amd64|386)\.exe'
            if ($appId -cne 'Tactical.Agent') { throw 'invalid PG_APP_ID for agent' }
        }
    }
    if ($path -match '(^|/)\.{1,2}(/|$)') { throw 'invalid PG_PATH (traversal)' }
    if ($kind -ne 'agent') { Assert-Match 'PG_PUBLISHER' $publisher "O=[A-Za-z0-9 .,&()'+-]{2,200}(?: ?; ?O=[A-Za-z0-9 .,&()'+-]{2,200}){0,3}" }

    $switches = @()
    if ($kind -eq 'exe') {
        $switches = @($argString.Trim() -split '\s+' | Where-Object { $_ })
        if ($switches.Count -eq 0 -or $switches.Count -gt 12) { throw 'invalid PG_ARGS' }
        foreach ($t in $switches) { if ($AllowedSwitches -cnotcontains $t) { throw "switch not allowed: $t" } }
    } elseif ($argString) {
        throw 'PG_ARGS only allowed for exe'
    }

    $runDir = Get-SecureRunDirectory
    $ext = if ($kind -eq 'msi') { 'msi' } else { 'exe' }
    $safeId = $appId -replace '[^A-Za-z0-9._-]', '_'
    $file = Join-Path $runDir ("{0}-{1}.{2}" -f $safeId, $version, $ext)
    $log = Join-Path $runDir 'install.log'

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -UseBasicParsing -Uri ("{0}/{1}" -f $repo, $path) -OutFile $file -MaximumRedirection 0

    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $file).Hash.ToLowerInvariant()
    if ($actual -ne $sha) { throw 'hash mismatch' }

    if ($kind -eq 'agent') {
        # The upgrade restarts the Tactical agent running this script: hand it to a one-time SYSTEM
        # task. The task re-checks the hash right before running, then removes the file and itself.
        $taskName = 'PatchGate-AgentUpgrade-' + [guid]::NewGuid().ToString('N')
        $q = { param($s) $s -replace "'", "''" }
        $taskScript = @"
`$ErrorActionPreference = 'Stop'
`$f = '$(& $q $file)'
if ((Get-FileHash -Algorithm SHA256 -LiteralPath `$f).Hash.ToLowerInvariant() -ne '$sha') { exit 99 }
`$p = Start-Process -FilePath `$f -ArgumentList @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/LOG="$(& $q $log)"') -PassThru
[void]`$p.WaitForExit(1800000)
Remove-Item -LiteralPath '$(& $q $runDir)' -Recurse -Force -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName '$taskName' -Confirm:`$false -ErrorAction SilentlyContinue
"@
        $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($taskScript))
        $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
            -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand $encoded"
        $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(30)
        $trigger.EndBoundary = (Get-Date).AddHours(24).ToString('s')
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
            -DeleteExpiredTaskAfter (New-TimeSpan -Hours 1) -ExecutionTimeLimit (New-TimeSpan -Minutes 40)
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
        $keepRunDir = $true
        Write-Result 'OK'
        exit 0
    }

    Assert-Publisher (Get-AuthenticodeSignature -LiteralPath $file) $publisher

    if ($kind -eq 'msi') {
        $proc = Start-Process -FilePath "$env:SystemRoot\System32\msiexec.exe" `
            -ArgumentList @('/i', "`"$file`"", '/qn', '/norestart', '/l*v', "`"$log`"") -PassThru
    } else {
        $proc = Start-Process -FilePath $file -ArgumentList $switches -PassThru
    }
    $exit = Wait-Installer $proc

    # 0 = success, 3010 = success (reboot required), 1641 = success (reboot initiated)
    if (@(0, 3010, 1641) -notcontains $exit) { throw ("installer exit " + $exit) }

    Write-Result 'OK'
    exit 0
}
catch {
    Write-Result ("FAIL:" + $_.Exception.Message)
    exit 1
}
finally {
    if (-not $keepRunDir -and $runDir -and (Test-Path -LiteralPath $runDir)) {
        Remove-Item -LiteralPath $runDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
