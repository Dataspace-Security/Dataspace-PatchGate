#Requires -Version 5.1
#Requires -Modules UpdateServices
<#
.SYNOPSIS
  Push the WSUS update catalog (metadata only) into PatchGate.

.DESCRIPTION
  Runs on the WSUS server inside the PatchGate zone. Schedule it with Task Scheduler to run
  right after each WSUS synchronization (e.g. daily 03:30), as a dedicated service account.

  Sends KB, title, classification, MSRC severity, release date and supersedence for every
  non-declined update in the chosen classifications. No content is transferred.

.PARAMETER PatchGateUrl
  e.g. https://patchgate.bank.local  (internal URL, TLS certificate must be trusted)

.PARAMETER TokenFile
  File holding WSUS_TOKEN (ACL: service account + Administrators only).
#>
param(
    [Parameter(Mandatory)][ValidatePattern('^https://[A-Za-z0-9.-]+(:\d{1,5})?$')][string]$PatchGateUrl,
    [string]$TokenFile = (Join-Path $env:ProgramData 'PatchGate\wsus-token.txt'),
    [ValidateRange(1, 1000)][int]$BatchSize = 500,
    [string[]]$Classifications = @('Security Updates', 'Critical Updates', 'Update Rollups', 'Definition Updates', 'Updates')
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$token = (Get-Content -LiteralPath $TokenFile -Raw).Trim()
if ($token.Length -lt 32) { throw 'WSUS token missing or too short' }

$wsus = Get-WsusServer
$scope = New-Object Microsoft.UpdateServices.Administration.UpdateScope
$supersedes = [Microsoft.UpdateServices.Administration.UpdateRelationship]::UpdatesThatSupersedeThisUpdate

$updates = $wsus.GetUpdates($scope) | Where-Object {
    -not $_.IsDeclined -and $Classifications -contains $_.UpdateClassificationTitle
}

function ConvertTo-PatchGateUpdate($u) {
    $supersededBy = $null
    if ($u.IsSuperseded) {
        $newer = $u.GetRelatedUpdates($supersedes) | Select-Object -First 1
        if ($newer) { $supersededBy = $newer.Id.UpdateId.Guid }
    }
    $kb = $u.KnowledgebaseArticles | Where-Object { $_ -match '^\d{4,8}$' } | Select-Object -First 1
    $title = if ($u.Title.Length -gt 500) { $u.Title.Substring(0, 500) } else { $u.Title }
    [ordered]@{
        updateId       = $u.Id.UpdateId.Guid
        title          = $title
        kb             = $kb
        classification = $u.UpdateClassificationTitle
        msrcSeverity   = if ($u.MsrcSeverity) { [string]$u.MsrcSeverity } else { $null }
        released       = $u.CreationDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        supersededBy   = $supersededBy
        cves           = @()
    }
}

$headers = @{ 'x-wsus-token' = $token }
$batch = New-Object System.Collections.Generic.List[object]
$sent = 0

function Send-Batch {
    if ($batch.Count -eq 0) { return }
    $body = @{ updates = @($batch) } | ConvertTo-Json -Depth 5 -Compress
    $null = Invoke-RestMethod -Method Post -Uri "$PatchGateUrl/api/wsus/catalog" -Headers $headers `
        -ContentType 'application/json; charset=utf-8' -Body ([Text.Encoding]::UTF8.GetBytes($body)) -MaximumRedirection 0
    $script:sent += $batch.Count
    $batch.Clear()
}

foreach ($u in $updates) {
    $batch.Add((ConvertTo-PatchGateUpdate $u))
    if ($batch.Count -ge $BatchSize) { Send-Batch }
}
Send-Batch

Write-Output "PatchGate catalog export complete: $sent updates"
