#Requires -Version 5.1
#Requires -Modules UpdateServices
<#
.SYNOPSIS
  Make WSUS approvals mirror PatchGate exactly (desired-state sync).

.DESCRIPTION
  Runs on the PatchGate-zone WSUS server every 5 minutes (Task Scheduler). PatchGate returns:
    groups    — every ring computer group PatchGate manages
    approvals — (updateId, wsusGroup) pairs for Windows patches in change requests that are
                currently DEPLOYING to that ring
  For each managed group this script:
    1. approves (Install) every desired update not yet approved, and
    2. REMOVES every Install approval that is not desired (CR completed/cancelled/rejected),
  so WSUS never offers PCs anything outside an active, approved rollout. This is a SECOND gate:
  even if Tactical were misused, PCs cannot download what PatchGate has not approved.

  Groups not in PatchGate's list are never touched. Updates are never declined.
  EULAs of desired updates are accepted on the bank's behalf — the acceptance is part of the
  approved change request (maker-checker) and is logged below.

  Trade-off (ARCHITECTURE R8): agent scans show only approved-but-missing updates; the full
  "needed" view comes from Export-WsusCatalog. Keep this schedule <= 10 minutes: PatchGate's
  deploy worker rescans agents for up to 3 rounds while waiting for these approvals.
#>
param(
    [Parameter(Mandatory)][ValidatePattern('^https://[A-Za-z0-9.-]+(:\d{1,5})?$')][string]$PatchGateUrl,
    [string]$TokenFile = (Join-Path $env:ProgramData 'PatchGate\wsus-token.txt')
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$GuidRe = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
$GroupRe = '^[A-Za-z0-9 _-]{1,64}$'
$Install = [Microsoft.UpdateServices.Administration.UpdateApprovalAction]::Install

$token = (Get-Content -LiteralPath $TokenFile -Raw).Trim()
if ($token.Length -lt 32) { throw 'WSUS token missing or too short' }

$resp = Invoke-RestMethod -Method Get -Uri "$PatchGateUrl/api/wsus/approvals" `
    -Headers @{ 'x-wsus-token' = $token } -MaximumRedirection 0
if (-not $resp.success) { throw "PatchGate error: $($resp.error)" }

$wsus = Get-WsusServer
$groupsByName = @{}
foreach ($g in $wsus.GetComputerTargetGroups()) { $groupsByName[$g.Name] = $g }

# Desired set per managed group: group -> HashSet[updateId lowercase]
$desired = @{}
foreach ($name in @($resp.data.groups)) {
    if ($name -notmatch $GroupRe) { Write-Warning "skip invalid group name"; continue }
    $desired[$name] = New-Object 'System.Collections.Generic.HashSet[string]'
    if (-not $groupsByName.ContainsKey($name)) {
        $groupsByName[$name] = $wsus.CreateComputerTargetGroup($name)
        Write-Output "Created WSUS group $name"
    }
}
foreach ($item in @($resp.data.approvals)) {
    if ($item.updateId -notmatch $GuidRe -or -not $desired.ContainsKey($item.wsusGroup)) { Write-Warning "skip invalid approval"; continue }
    [void]$desired[$item.wsusGroup].Add($item.updateId.ToLowerInvariant())
}

$approved = 0
$revoked = 0
foreach ($name in $desired.Keys) {
    $group = $groupsByName[$name]

    # 1. Revoke Install approvals that are no longer desired in this managed group.
    $scope = New-Object Microsoft.UpdateServices.Administration.UpdateApprovalScope
    [void]$scope.ComputerTargetGroups.Add($group)
    foreach ($appr in $wsus.GetUpdateApprovals($scope)) {
        if ($appr.Action -ne $Install) { continue }
        $id = $appr.UpdateId.UpdateId.Guid.ToLowerInvariant()
        if (-not $desired[$name].Contains($id)) {
            $appr.Delete()
            $revoked++
            Write-Output "Revoked $id from $name"
        }
    }

    # 2. Approve desired updates not yet approved.
    foreach ($id in $desired[$name]) {
        $update = Get-WsusUpdate -UpdateId $id -ErrorAction SilentlyContinue
        if (-not $update) { Write-Warning "update $id not in WSUS (sync pending?)"; continue }
        $already = $update.Update.GetUpdateApprovals($group) | Where-Object { $_.Action -eq $Install }
        if ($already) { continue }
        if ($update.Update.RequiresLicenseAgreementAcceptance) {
            $update.Update.AcceptLicenseAgreement()
            Write-Output "Accepted EULA for $id (approved change request)"
        }
        Approve-WsusUpdate -Update $update -Action Install -TargetGroupName $name
        $approved++
    }
}

Write-Output "PatchGate approval sync complete: $approved approved, $revoked revoked"
