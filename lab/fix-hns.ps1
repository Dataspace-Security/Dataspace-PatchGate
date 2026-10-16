#Requires -RunAsAdministrator
# Repair Windows Sandbox / Hyper-V "Default Switch" networking when HNS logs
# "HNS failed to create vmswitch ... 0x8007023E" (ghost "vEthernet (Default Switch)" adapter).
# Safe: removes only NOT-PRESENT Hyper-V virtual adapters and sets the HNS state file aside (renamed, not deleted).
$ErrorActionPreference = 'Continue'

Write-Output 'Stopping Host Network Service (hns)...'
Stop-Service hns -Force

$ghosts = Get-PnpDevice -Class Net | Where-Object { $_.FriendlyName -like 'Hyper-V Virtual Ethernet Adapter*' -and $_.Status -ne 'OK' }
if (-not $ghosts) { Write-Output 'No ghost Hyper-V adapters found.' }
foreach ($g in $ghosts) {
    Write-Output ("Removing ghost adapter: {0}  [{1}]" -f $g.FriendlyName, $g.InstanceId)
    pnputil /remove-device $g.InstanceId
}

$state = 'C:\ProgramData\Microsoft\Windows\HNS\HNS.data'
if (Test-Path $state) {
    $bak = 'HNS.data.bak-' + (Get-Date -Format yyyyMMddHHmmss)
    Rename-Item $state $bak
    Write-Output "HNS state set aside as $bak"
} else {
    Write-Output 'No HNS state file present.'
}

Write-Output 'Starting Host Network Service...'
Start-Service hns
Start-Sleep -Seconds 10
Write-Output '--- HNS networks now:'
hnsdiag list networks
Write-Output '--- Hyper-V adapters now:'
Get-NetAdapter | Where-Object { $_.Name -like 'vEthernet*' } | Format-Table Name, Status -AutoSize
