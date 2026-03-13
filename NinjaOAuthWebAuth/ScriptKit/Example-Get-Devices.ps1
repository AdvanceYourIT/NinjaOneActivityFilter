[CmdletBinding()]
param(
    [string]$TenantDomain = 'eu.ninjarmm.com',
    [int]$PageSize = 50
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'WebAuth-Common.ps1')

$session = Initialize-NinjaWebAuthSession -TenantDomain $TenantDomain -ShowConfigSummary
$result = Invoke-NinjaWebAuthApiGet -Session $session -PathAndQuery "/v2/devices?pageSize=$PageSize"

Write-Host "Devices (pageSize=$PageSize):" -ForegroundColor Green
$result
