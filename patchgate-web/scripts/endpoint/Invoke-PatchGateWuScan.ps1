#Requires -Version 5.1
<#
.SYNOPSIS
  PatchGate offline Windows Update scan. Runs on offline bank PCs as SYSTEM via Tactical RMM. READ-ONLY:
  it never downloads from the internet and never installs anything.

.DESCRIPTION
  Register ONCE in Tactical (shell: PowerShell), code-sign it with the bank's signing certificate and put
  its Tactical script id in the connector config (tactical.wuScanScriptId).

  1. Fetches Microsoft's offline scan catalog (wsusscn2.cab) from the site's PatchGate Connector cache
     (PG_REPO_URL, never the internet), keeps ONE verified copy in %ProgramData%\PatchGate\wsusscan
     (SYSTEM + Administrators only) so the next scan does not download ~700 MB again.
  2. Verifies SHA-256 (from the signed job) + Authenticode Valid + signer organisation exactly
     "Microsoft Corporation".
  3. Registers the cab as a temporary offline scan service (Microsoft.Update.ServiceManager
     AddScanPackageService), searches "IsInstalled=0 and IsHidden=0" with ServerSelection=3 (ssOthers) +
     that ServiceID, and ALWAYS unregisters the service again (also stale ones from a crashed earlier run).
  4. Prints exactly one line: PATCHGATE_RESULT=<json>
       {"ok":true,"updates":[{updateId,revision,kb,title,msrcSeverity,classification,
                               files:[{url,name,size,sha1,sha256}]}]}
       {"ok":false,"error":"..."}
     Only .msu/.cab full (non-delta) payloads are reported; PatchGate fetches them, the PC never does.

  Inputs (environment variables only):
    PG_REPO_URL          https://connector.bank.local:8443/repo   (site cache)
    PG_PATH              winupdate/wsusscan/<16 hex>/wsusscn2.cab
    PG_SHA256            64 lowercase hex
    PG_SCAN_TIMEOUT_SEC  optional, 60..7000 (default 2400)
    PG_CAB_FILE          optional, local validation only: absolute path of an already present cab
                         (still hash- and signature-verified; PG_REPO_URL / PG_PATH are then not used)
#>

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$Publisher = 'Microsoft Corporation'
$ServiceName = 'PatchGate Offline Scan'
$MaxUpdates = 1000
$MaxFilesPerUpdate = 20
$SidSystem = 'S-1-5-18'
$SidAdmins = 'S-1-5-32-544'

function Write-Result($Object) {
    $json = $Object | ConvertTo-Json -Depth 8 -Compress
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

# A directory under %ProgramData%\PatchGate that only SYSTEM/Administrators can touch (moved aside if not).
function Get-SecureDirectory([string]$Leaf) {
    $root = Join-Path $env:ProgramData 'PatchGate'
    foreach ($dir in @($root, (Join-Path $root $Leaf))) {
        if ((Test-Path -LiteralPath $dir) -and -not (Test-TrustedAcl $dir)) {
            Rename-Item -LiteralPath $dir -NewName ((Split-Path $dir -Leaf) + '.untrusted-' + [guid]::NewGuid().ToString('N'))
        }
        if (-not (Test-Path -LiteralPath $dir)) { [void][System.IO.Directory]::CreateDirectory($dir, (New-SecureDirectorySecurity)) }
        if (-not (Test-TrustedAcl $dir)) { throw 'PatchGate folder ACL is not trusted' }
    }
    return (Join-Path $root $Leaf)
}

function Assert-Microsoft([string]$File) {
    $sig = Get-AuthenticodeSignature -LiteralPath $File
    if ($sig.Status -ne 'Valid') { throw ('signature ' + $sig.Status) }
    $rdns = $sig.SignerCertificate.SubjectName.Decode(
        [System.Security.Cryptography.X509Certificates.X500DistinguishedNameFlags]::UseNewLines) -split "`r?`n"
    $orgs = @($rdns | Where-Object { $_ -like 'O=*' } | ForEach-Object { $_.Substring(2).Trim().Trim('"') })
    if (-not ($orgs | Where-Object { $_ -ieq $Publisher })) { throw 'publisher mismatch' }
}

function Get-Sha256([string]$File) { (Get-FileHash -Algorithm SHA256 -LiteralPath $File).Hash.ToLowerInvariant() }

# Download from the site cache; the cache answers 503 + Retry-After when busy.
function Get-CacheFile([string]$Url, [string]$OutFile) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    for ($i = 1; $i -le 6; $i++) {
        try {
            Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $OutFile -MaximumRedirection 0 -TimeoutSec 1800
            return
        } catch {
            $status = $null
            try { $status = [int]$_.Exception.Response.StatusCode } catch { }
            Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue
            if ($i -eq 6 -or ($status -and $status -ne 503 -and $status -ne 429)) { throw }
            Start-Sleep -Seconds ([Math]::Min(300, 15 * $i + (Get-Random -Maximum 15)))
        }
    }
}

function Remove-StaleScanServices($Manager) {
    foreach ($s in @($Manager.Services)) {
        if ($s.Name -eq $ServiceName) { try { $Manager.RemoveService($s.ServiceID) } catch { } }
    }
}

# Runs in a child process (Start-Job) so a hung search can be killed at the deadline.
$SearchBlock = {
    param([string]$ServiceId, [int]$MaxUpdates, [int]$MaxFiles)
    $ErrorActionPreference = 'Stop'
    $session = New-Object -ComObject Microsoft.Update.Session
    $session.ClientApplicationID = 'PatchGate'
    $searcher = $session.CreateUpdateSearcher()
    $searcher.ServerSelection = 3   # ssOthers
    $searcher.ServiceID = $ServiceId
    $searcher.Online = $false
    $result = $searcher.Search('IsInstalled=0 and IsHidden=0')
    if ($result.ResultCode -ne 2 -and $result.ResultCode -ne 3) { throw ('search result code ' + $result.ResultCode) }

    $out = New-Object System.Collections.ArrayList
    foreach ($u in $result.Updates) {
        if ($out.Count -ge $MaxUpdates) { break }
        $files = New-Object System.Collections.ArrayList
        $seen = @{}
        $sources = @($u) + @($u.BundledUpdates)
        foreach ($src in $sources) {
            foreach ($c in @($src.DownloadContents)) {
                if ($null -eq $c -or $files.Count -ge $MaxFiles) { continue }
                $delta = $false
                try { $delta = [bool]$c.IsDeltaCompressedContent } catch { }
                $url = [string]$c.DownloadUrl
                if ($delta -or -not $url -or $seen.ContainsKey($url)) { continue }
                $name = ($url -split '/')[-1]
                if ($name -notmatch '\.(msu|cab)$') { continue }
                $seen[$url] = $true
                $sha1 = $null
                if ($name -match '_([0-9a-fA-F]{40})\.[A-Za-z0-9]+$') { $sha1 = $Matches[1].ToLowerInvariant() }
                [void]$files.Add([ordered]@{ url = $url; name = $name.Substring(0, [Math]::Min(260, $name.Length)); size = 0; sha1 = $sha1; sha256 = $null })
            }
        }
        $kb = $null
        if ($u.KBArticleIDs.Count -gt 0) { $kb = 'KB' + [string]$u.KBArticleIDs.Item(0) }
        if ($kb -and $kb.Length -gt 16) { $kb = $null }
        $classification = $null
        foreach ($cat in $u.Categories) { if ($cat.Type -eq 'UpdateClassification') { $classification = [string]$cat.Name; break } }
        $sev = [string]$u.MsrcSeverity
        $title = [string]$u.Title
        [void]$out.Add([ordered]@{
            updateId       = [string]$u.Identity.UpdateID
            revision       = [int]$u.Identity.RevisionNumber
            kb             = $kb
            title          = $title.Substring(0, [Math]::Min(1000, $title.Length))
            msrcSeverity   = $(if ($sev) { $sev.Substring(0, [Math]::Min(32, $sev.Length)) } else { $null })
            classification = $(if ($classification) { $classification.Substring(0, [Math]::Min(100, $classification.Length)) } else { $null })
            files          = @($files)
        })
    }
    # One JSON string: survives the job boundary without deserialisation surprises.
    ConvertTo-Json -InputObject @($out) -Depth 8 -Compress
}

$runDir = $null
$manager = $null
$serviceId = $null
try {
    $sha = $env:PG_SHA256
    Assert-Match 'PG_SHA256' $sha '[a-f0-9]{64}'
    $timeoutSec = 2400
    if ($env:PG_SCAN_TIMEOUT_SEC) {
        Assert-Match 'PG_SCAN_TIMEOUT_SEC' $env:PG_SCAN_TIMEOUT_SEC '[0-9]{2,4}'
        $timeoutSec = [int]$env:PG_SCAN_TIMEOUT_SEC
        if ($timeoutSec -lt 60 -or $timeoutSec -gt 7000) { throw 'invalid PG_SCAN_TIMEOUT_SEC' }
    }

    if ($env:PG_CAB_FILE) {
        $cab = $env:PG_CAB_FILE
        if (-not [System.IO.Path]::IsPathRooted($cab) -or -not (Test-Path -LiteralPath $cab -PathType Leaf)) { throw 'invalid PG_CAB_FILE' }
        if ((Get-Sha256 $cab) -ne $sha) { throw 'hash mismatch' }
    } else {
        $repo = $env:PG_REPO_URL
        $path = $env:PG_PATH
        Assert-Match 'PG_REPO_URL' $repo 'https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._-]+)*'
        Assert-Match 'PG_PATH' $path 'winupdate/wsusscan/[a-f0-9]{16}/wsusscn2\.cab'
        $store = Get-SecureDirectory 'wsusscan'
        $cab = Join-Path $store ($sha + '.cab')
        if ((Test-Path -LiteralPath $cab) -and ((Get-Sha256 $cab) -ne $sha)) { Remove-Item -LiteralPath $cab -Force }
        if (-not (Test-Path -LiteralPath $cab)) {
            $runDir = Join-Path $store ('dl-' + [guid]::NewGuid().ToString('N'))
            [void][System.IO.Directory]::CreateDirectory($runDir, (New-SecureDirectorySecurity))
            $tmp = Join-Path $runDir 'wsusscn2.cab'
            Get-CacheFile ('{0}/{1}' -f $repo, $path) $tmp
            if ((Get-Sha256 $tmp) -ne $sha) { throw 'hash mismatch' }
            Move-Item -LiteralPath $tmp -Destination $cab -Force
        }
        # Keep exactly one catalog on disk.
        Get-ChildItem -LiteralPath $store -Filter '*.cab' | Where-Object { $_.Name -ne ($sha + '.cab') } | Remove-Item -Force -ErrorAction SilentlyContinue
        if ((Get-Sha256 $cab) -ne $sha) { throw 'hash mismatch' }   # re-check right before use
    }
    Assert-Microsoft $cab

    $manager = New-Object -ComObject Microsoft.Update.ServiceManager
    $manager.ClientApplicationID = 'PatchGate'
    Remove-StaleScanServices $manager
    $service = $manager.AddScanPackageService($ServiceName, $cab, 1)
    $serviceId = [string]$service.ServiceID

    $job = Start-Job -ScriptBlock $SearchBlock -ArgumentList $serviceId, $MaxUpdates, $MaxFilesPerUpdate
    if (-not (Wait-Job -Job $job -Timeout $timeoutSec)) {
        Stop-Job -Job $job
        Remove-Job -Job $job -Force
        throw 'scan timed out'
    }
    if ($job.State -ne 'Completed') {
        $reason = ($job.ChildJobs[0].JobStateInfo.Reason | Out-String).Trim()
        Remove-Job -Job $job -Force
        throw ('scan failed: ' + $reason)
    }
    $json = [string](Receive-Job -Job $job -ErrorAction Stop | Select-Object -Last 1)
    Remove-Job -Job $job -Force
    if (-not $json.StartsWith('[')) { throw 'scan produced no result' }
    # Embed the job's JSON array verbatim (it is already compact JSON).
    Write-Output ('PATCHGATE_RESULT={"ok":true,"updates":' + ($json -replace '[\r\n]', ' ') + '}')
    exit 0
}
catch {
    $msg = ($_.Exception.Message -replace '[\r\n]+', ' ')
    Write-Result ([ordered]@{ ok = $false; error = $msg.Substring(0, [Math]::Min(1500, $msg.Length)) })
    exit 1
}
finally {
    if ($manager -and $serviceId) { try { $manager.RemoveService($serviceId) } catch { } }
    if ($runDir -and (Test-Path -LiteralPath $runDir)) { Remove-Item -LiteralPath $runDir -Recurse -Force -ErrorAction SilentlyContinue }
}
