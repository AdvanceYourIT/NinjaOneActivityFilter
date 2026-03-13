[CmdletBinding()]
param(
    [string]$TenantDomain = 'eu.ninjarmm.com'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'WebAuth-Common.ps1')

$session = Initialize-NinjaWebAuthSession -TenantDomain $TenantDomain -ShowConfigSummary
$result = Invoke-NinjaWebAuthApiGet -Session $session -PathAndQuery '/v2/organizations'

Write-Host 'Organizations (first 20):' -ForegroundColor Green
$result | Select-Object -First 20
