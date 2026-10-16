#Requires -Version 5.1
<#
.SYNOPSIS
  PatchGate Windows update installer. Runs on offline bank PCs as SYSTEM via Tactical RMM.

.DESCRIPTION
  Register ONCE in Tactical (shell: PowerShell), code-sign it with the bank's signing certificate and put
  its Tactical script id in the connector config (tactical.wuInstallScriptId).

  Installs approved Microsoft update files that the site's PatchGate Connector cache holds (PG_REPO_URL —
  never the internet). For every file: download from the cache into a per-run folder (SYSTEM +
  Administrators only), SHA-256 must equal the signed job's value, Authenticode must be Valid and signed by
  organisation exactly "Microsoft Corporation". Then:
    .msu  wusa.exe <file> /quiet /norestart
    .cab  DISM.exe /Online /Add-Package /PackagePath:<file> /Quiet /NoRestart
  Safe to re-run: an update whose KB is already installed (Get-HotFix / DISM package list) is skipped and
  reported as installed; wusa "already installed" (0x240006) counts as installed too.

  Inputs (environment variables only):
    PG_REPO_URL      https://connector.bank.local:8443/repo   (site cache)
    PG_UPDATES       ';'-separated files, in install order, each
                     <updateId>,<KB1234567|->,<msu|cab>,<sha256>,<size>,winupdate/<updateId>/<file>
    PG_REBOOT        NEVER | IF_REQUIRED | FORCE   (restart 120 s after the script, if applicable)
    PG_DEADLINE_SEC  optional, 60..7000: stop starting new installs after this many seconds (default 3300)

  Prints exactly one line:
    PATCHGATE_RESULT={"ok":true,"installed":[ids],"skipped":[ids],"failed":[{"updateId","error"}],"rebootRequired":bool,"rebootScheduled":bool}
    PATCHGATE_RESULT={"ok":false,"error":"..."}       (input / environment problem: nothing was installed)
#>

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$Publisher = 'Microsoft Corporation'
$MaxFiles = 100
$SidSystem = 'S-1-5-18'
$SidAdmins = 'S-1-5-32-544'
$Guid = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
$FileRe = "($Guid),(KB[0-9]{4,8}|-),(msu|cab),([a-f0-9]{64}),([0-9]{1,10}),(winupdate/$Guid/[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9_-])?)"

function Write-Result($Object) {
    $json = $Object | ConvertTo-Json -Depth 6 -Compress
    Write-Output ('PATCHGATE_RESULT=' + ($json -replace '[\r\n]', ' '))
}

function Assert-Match([string]$Name, [string]$Value, [string]$Pattern) {
    if ([string]::IsNullOrEmpty($Value) -or -not [regex]::IsMatch($Value, "\A(?:$Pattern)\z", 'CultureInvariant')) {
        throw "invalid $Name"
    }
}

function New-SecureDirectorySecurity {
    $sec = New-Object System.Security.AccessControl.DirectorySecurity
    $sec.SetAccessRuleProtection($true, $false)
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

function Get-SecureRunDirectory {
    $root = Join-Path $env:ProgramData 'PatchGate'
    if ((Test-Path -LiteralPath $root) -and -not (Test-TrustedAcl $root)) {
        Rename-Item -LiteralPath $root -NewName ('PatchGate.untrusted-' + [guid]::NewGuid().ToString('N'))
    }
    if (-not (Test-Path -LiteralPath $root)) { [void][System.IO.Directory]::CreateDirectory($root, (New-SecureDirectorySecurity)) }
    if (-not (Test-TrustedAcl $root)) { throw 'PatchGate folder ACL is not trusted' }
    $run = Join-Path $root ('wu-' + [guid]::NewGuid().ToString('N'))
    [void][System.IO.Directory]::CreateDirectory($run, (New-SecureDirectorySecurity))
    if (-not (Test-TrustedAcl $run)) { throw 'run folder ACL is not trusted' }
    return $run
}

function Assert-Microsoft([string]$File) {
    $sig = Get-AuthenticodeSignature -LiteralPath $File
    if ($sig.Status -ne 'Valid') { throw ('signature ' + $sig.Status) }
    $rdns = $sig.SignerCertificate.SubjectName.Decode(
        [System.Security.Cryptography.X509Certificates.X500DistinguishedNameFlags]::UseNewLines) -split "`r?`n"
    $orgs = @($rdns | Where-Object { $_ -like 'O=*' } | ForEach-Object { $_.Substring(2).Trim().Trim('"') })
    if (-not ($orgs | Where-Object { $_ -ieq $Publisher })) { throw 'publisher mismatch' }
}

function Get-CacheFile([string]$Url, [string]$OutFile) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    for ($i = 1; $i -le 5; $i++) {
        try {
            Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $OutFile -MaximumRedirection 0 -TimeoutSec 1800
            return
        } catch {
            $status = $null
            try { $status = [int]$_.Exception.Response.StatusCode } catch { }
            Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue
            if ($i -eq 5 -or ($status -and $status -ne 503 -and $status -ne 429)) { throw }
            Start-Sleep -Seconds ([Math]::Min(120, 10 * $i + (Get-Random -Maximum 10)))
        }
    }
}

# KBs Windows reports as installed (QFE list + DISM servicing packages).
function Get-InstalledKbs {
    $set = @{}
    try { foreach ($h in @(Get-HotFix -ErrorAction Stop)) { if ($h.HotFixID -match '^KB\d+$') { $set[$h.HotFixID.ToUpperInvariant()] = $true } } } catch { }
    try {
        foreach ($p in @(Get-WindowsPackage -Online -ErrorAction Stop)) {
            if ($p.PackageState -eq 'Installed' -and $p.PackageName -match '(?i)KB(\d{4,8})') { $set['KB' + $Matches[1]] = $true }
        }
    } catch { }
    return $set
}

function Test-RebootPending {
    $keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    )
    foreach ($k in $keys) { if (Test-Path -LiteralPath $k) { return $true } }
    return $false
}

function Invoke-Installer([string]$Kind, [string]$File, [int]$TimeoutMs) {
    if ($Kind -eq 'msu') {
        $proc = Start-Process -FilePath "$env:SystemRoot\System32\wusa.exe" -ArgumentList @("`"$File`"", '/quiet', '/norestart') -PassThru -WindowStyle Hidden
    } else {
        $proc = Start-Process -FilePath "$env:SystemRoot\System32\Dism.exe" -ArgumentList @('/Online', '/Add-Package', "/PackagePath:`"$File`"", '/Quiet', '/NoRestart') -PassThru -WindowStyle Hidden
    }
    if (-not $proc.WaitForExit($TimeoutMs)) {
        try { $proc.Kill() } catch { }
        throw 'installer timed out'
    }
    return $proc.ExitCode
}

$runDir = $null
try {
    $started = Get-Date
    $repo = $env:PG_REPO_URL
    $reboot = $env:PG_REBOOT
    Assert-Match 'PG_REPO_URL' $repo 'https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._-]+)*'
    Assert-Match 'PG_REBOOT' $reboot 'NEVER|IF_REQUIRED|FORCE'
    $deadlineSec = 3300
    if ($env:PG_DEADLINE_SEC) {
        Assert-Match 'PG_DEADLINE_SEC' $env:PG_DEADLINE_SEC '[0-9]{2,4}'
        $deadlineSec = [int]$env:PG_DEADLINE_SEC
        if ($deadlineSec -lt 60 -or $deadlineSec -gt 7000) { throw 'invalid PG_DEADLINE_SEC' }
    }
    Assert-Match 'PG_UPDATES' $env:PG_UPDATES "$FileRe(;$FileRe){0,$($MaxFiles - 1)}"

    # Group files per update, preserving order.
    $order = New-Object System.Collections.ArrayList
    $byUpdate = @{}
    foreach ($entry in ($env:PG_UPDATES -split ';')) {
        $m = [regex]::Match($entry, "\A$FileRe\z", 'CultureInvariant')
        $f = [pscustomobject]@{ UpdateId = $m.Groups[1].Value; Kb = $m.Groups[2].Value; Kind = $m.Groups[3].Value; Sha = $m.Groups[4].Value; Size = [long]$m.Groups[5].Value; Path = $m.Groups[6].Value }
        if (-not $f.Path.StartsWith('winupdate/' + $f.UpdateId + '/')) { throw 'invalid PG_UPDATES (path does not belong to update)' }
        if (-not $f.Path.EndsWith('.' + $f.Kind)) { throw 'invalid PG_UPDATES (kind does not match file)' }
        if (-not $byUpdate.ContainsKey($f.UpdateId)) { $byUpdate[$f.UpdateId] = New-Object System.Collections.ArrayList; [void]$order.Add($f.UpdateId) }
        [void]$byUpdate[$f.UpdateId].Add($f)
    }

    $runDir = Get-SecureRunDirectory
    $installedKbs = Get-InstalledKbs
    $installed = New-Object System.Collections.ArrayList
    $skipped = New-Object System.Collections.ArrayList
    $failed = New-Object System.Collections.ArrayList
    $needsReboot = $false

    foreach ($id in $order) {
        $files = $byUpdate[$id]
        $kb = $files[0].Kb
        if ($kb -ne '-' -and $installedKbs.ContainsKey($kb)) { [void]$skipped.Add($id); continue }
        $remaining = $deadlineSec - ((Get-Date) - $started).TotalSeconds
        if ($remaining -lt 60) { [void]$failed.Add([ordered]@{ updateId = $id; error = 'deadline reached before install (retry)' }); continue }
        try {
            $already = $true
            foreach ($f in $files) {
                $local = Join-Path $runDir ([guid]::NewGuid().ToString('N') + '.' + $f.Kind)
                Get-CacheFile ('{0}/{1}' -f $repo, $f.Path) $local
                if ((Get-Item -LiteralPath $local).Length -ne $f.Size) { throw 'size mismatch' }
                if ((Get-FileHash -Algorithm SHA256 -LiteralPath $local).Hash.ToLowerInvariant() -ne $f.Sha) { throw 'hash mismatch' }
                Assert-Microsoft $local
                $timeoutMs = [int][Math]::Max(60000, ($deadlineSec - ((Get-Date) - $started).TotalSeconds) * 1000)
                $exit = Invoke-Installer $f.Kind $local $timeoutMs
                Remove-Item -LiteralPath $local -Force -ErrorAction SilentlyContinue
                switch ($exit) {
                    0 { $already = $false }
                    3010 { $already = $false; $needsReboot = $true }
                    1641 { $already = $false; $needsReboot = $true }
                    2359302 { }   # WU_S_ALREADY_INSTALLED (0x00240006)
                    -2145124329 { throw 'update is not applicable to this computer (0x80240017)' }
                    default { throw ('installer exit 0x{0:X8}' -f $exit) }
                }
            }
            if ($already) { [void]$skipped.Add($id) } else { [void]$installed.Add($id) }
        } catch {
            $msg = ($_.Exception.Message -replace '[\r\n]+', ' ')
            [void]$failed.Add([ordered]@{ updateId = $id; error = $msg.Substring(0, [Math]::Min(500, $msg.Length)) })
        }
    }

    $rebootRequired = $needsReboot -or (Test-RebootPending)
    $scheduled = $false
    # FORCE: restart after installing anything, or when an earlier batch of this job left a restart pending.
    if (($reboot -eq 'FORCE' -and ($installed.Count -gt 0 -or $rebootRequired)) -or ($reboot -eq 'IF_REQUIRED' -and $rebootRequired)) {
        & "$env:SystemRoot\System32\shutdown.exe" /r /t 120 /d p:2:17 /c 'PatchGate: restart to complete Windows updates' | Out-Null
        $scheduled = ($LASTEXITCODE -eq 0)
    }
    Write-Result ([ordered]@{ ok = $true; installed = @($installed); skipped = @($skipped); failed = @($failed); rebootRequired = [bool]$rebootRequired; rebootScheduled = $scheduled })
    exit 0
}
catch {
    $msg = ($_.Exception.Message -replace '[\r\n]+', ' ')
    Write-Result ([ordered]@{ ok = $false; error = $msg.Substring(0, [Math]::Min(1500, $msg.Length)) })
    exit 1
}
finally {
    if ($runDir -and (Test-Path -LiteralPath $runDir)) { Remove-Item -LiteralPath $runDir -Recurse -Force -ErrorAction SilentlyContinue }
}
