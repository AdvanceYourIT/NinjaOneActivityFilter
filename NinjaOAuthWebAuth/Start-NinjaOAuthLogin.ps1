#Requires -Version 7.0
[CmdletBinding()]
param(
    [switch]$UseTokenCache,
    [string]$SampleApiUri
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. "$PSScriptRoot/Config.ps1"
Import-Module "$PSScriptRoot/NinjaOAuth.psm1" -Force

function Get-MaskedClientId {
    param([AllowNull()][AllowEmptyString()][string]$ClientId)

    if ([string]::IsNullOrWhiteSpace($ClientId)) { return '<empty>' }

    $trimmed = $ClientId.Trim()
    if ($trimmed.Length -le 8) { return ('*' * $trimmed.Length) }

    return ('{0}...{1}' -f $trimmed.Substring(0, 4), $trimmed.Substring($trimmed.Length - 4))
}

function Get-ClientIdSource {
    param([AllowNull()][AllowEmptyString()][string]$ResolvedClientId)

    $envClientId = [string]$env:NINJA_CLIENT_ID
    if ([string]::IsNullOrWhiteSpace($envClientId)) {
        return 'config-file'
    }

    if ($envClientId -eq [string]$ResolvedClientId) {
        return 'environment-variable (NINJA_CLIENT_ID)'
    }

    return 'config-file (NINJA_CLIENT_ID is set but differs)'
}

if ([string]::IsNullOrWhiteSpace($NinjaClientId)) {
    throw 'Ninja client ID is missing. Set $NinjaClientId in Config.ps1 or NINJA_CLIENT_ID env var.'
}
if ([string]::IsNullOrWhiteSpace($NinjaClientSecret)) {
    throw 'Ninja client secret is missing. Set $NinjaClientSecret in Config.ps1 or NINJA_CLIENT_SECRET env var.'
}
if ([string]::IsNullOrWhiteSpace($NinjaRedirectUri)) {
    throw 'Ninja redirect URI is missing in Config.ps1.'
}

if ([string]::IsNullOrWhiteSpace($SampleApiUri)) {
    $tokenUriHost = ([Uri]$NinjaTokenUrl).Host
    $SampleApiUri = "https://$tokenUriHost/v2/organizations"
}

$redirectUriObj = [Uri]$NinjaRedirectUri
if ($redirectUriObj.Host -notin @('localhost', '127.0.0.1')) {
    throw "For local callback safety, redirect URI host must be localhost or 127.0.0.1. Current host: $($redirectUriObj.Host)"
}

if ($UseTokenCache -and (Test-Path -LiteralPath $NinjaTokenCachePath)) {
    try {
        Write-Host 'Loading token cache...' -ForegroundColor Cyan
        $token = Load-NinjaTokenCache -Path $NinjaTokenCachePath
        Write-Host 'Token cache loaded.' -ForegroundColor Green
    }
    catch {
        Write-Warning "Token cache could not be loaded: $($_.Exception.Message)"
    }
}

$tokenReady = $false
if ($token) {
    try {
        $null = Get-ValidNinjaAccessToken -TokenEndpoint $NinjaTokenUrl -ClientId $NinjaClientId -ClientSecret $NinjaClientSecret -TimeoutSeconds $NinjaHttpTimeoutSeconds
        $tokenReady = $true
    }
    catch {
        Write-Warning "Cached token is not usable: $($_.Exception.Message)"
    }
}

if (-not $tokenReady) {
    $maskedClientId = Get-MaskedClientId -ClientId $NinjaClientId
    $clientIdSource = Get-ClientIdSource -ResolvedClientId $NinjaClientId
    Write-Host "OAuth configuration check: auth=$NinjaAuthUrl token=$NinjaTokenUrl clientId=$maskedClientId source=$clientIdSource redirect=$NinjaRedirectUri" -ForegroundColor DarkCyan

    $state = New-NinjaOAuthState
    $authorizeUrl = Get-NinjaAuthorizationUrl -ClientId $NinjaClientId -RedirectUri $NinjaRedirectUri -Scopes $NinjaScopes -State $state -AuthorizationEndpoint $NinjaAuthUrl

    Write-Host 'Opening browser for NinjaOne sign-in...' -ForegroundColor Cyan
    $null = Start-NinjaOAuthLogin -AuthorizationUrl $authorizeUrl

    Write-Host "Waiting for callback on $NinjaRedirectUri (timeout: $NinjaCallbackTimeoutSeconds seconds)..." -ForegroundColor Yellow
    $callback = Wait-NinjaOAuthCallback -RedirectUri $NinjaRedirectUri -TimeoutSeconds $NinjaCallbackTimeoutSeconds

    if (-not (Test-NinjaOAuthState -ExpectedState $state -ReturnedState $callback.State)) {
        throw 'OAuth state validation failed. Authentication aborted to prevent CSRF risk.'
    }

    Write-Host 'State validated. Requesting OAuth tokens...' -ForegroundColor Cyan
    $token = Request-NinjaOAuthToken -TokenEndpoint $NinjaTokenUrl -ClientId $NinjaClientId -ClientSecret $NinjaClientSecret -Code $callback.Code -RedirectUri $NinjaRedirectUri -TimeoutSeconds $NinjaHttpTimeoutSeconds

    Write-Host 'Authentication completed successfully.' -ForegroundColor Green

    if ($UseTokenCache) {
        try {
            $null = Save-NinjaTokenCache -Path $NinjaTokenCachePath -TokenInfo $token
            Write-Host "Token cache saved to $NinjaTokenCachePath" -ForegroundColor Green
        }
        catch {
            Write-Warning "Token cache could not be saved: $($_.Exception.Message)"
        }
    }
}

$accessToken = Get-ValidNinjaAccessToken -TokenEndpoint $NinjaTokenUrl -ClientId $NinjaClientId -ClientSecret $NinjaClientSecret -TimeoutSeconds $NinjaHttpTimeoutSeconds

Write-Host "Running sample NinjaOne API call: GET $SampleApiUri" -ForegroundColor Cyan
$apiResult = Invoke-NinjaApiRequest -Method GET -Uri $SampleApiUri -AccessToken $accessToken -TimeoutSeconds $NinjaHttpTimeoutSeconds

[pscustomobject]@{
    Authenticated      = $true
    Scope              = $token.scope
    ExpiresInSeconds   = $token.expires_in
    ApiUri             = $SampleApiUri
    ApiResultPreview   = if ($apiResult -is [System.Array]) { $apiResult | Select-Object -First 3 } else { $apiResult }
}
