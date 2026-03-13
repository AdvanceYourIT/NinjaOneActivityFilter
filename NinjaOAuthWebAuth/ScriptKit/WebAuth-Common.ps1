Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-ScriptKitPathSet {
    [CmdletBinding()]
    param()

    $localConfig = Join-Path $PSScriptRoot 'Config.ps1'
    $localModule = Join-Path $PSScriptRoot 'Dependencies/NinjaOAuth.psm1'
    $parentConfig = Join-Path $PSScriptRoot '..' 'Config.ps1'
    $parentModule = Join-Path $PSScriptRoot '..' 'NinjaOAuth.psm1'

    $configPath = if (Test-Path -LiteralPath $localConfig) { $localConfig } else { $parentConfig }
    $modulePath = if (Test-Path -LiteralPath $localModule) { $localModule } else { $parentModule }

    if (-not (Test-Path -LiteralPath $configPath)) {
        throw "Config.ps1 not found. Expected one of: $localConfig or $parentConfig"
    }
    if (-not (Test-Path -LiteralPath $modulePath)) {
        throw "NinjaOAuth.psm1 not found. Expected one of: $localModule or $parentModule"
    }

    return [pscustomobject]@{
        ConfigPath = $configPath
        ModulePath = $modulePath
    }
}

function Initialize-NinjaWebAuthSession {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TenantDomain,
        [switch]$ShowConfigSummary
    )

    $pathSet = Get-ScriptKitPathSet
    . $pathSet.ConfigPath
    Import-Module $pathSet.ModulePath -Force

    if ([string]::IsNullOrWhiteSpace($NinjaClientId)) {
        throw 'NinjaClientId is empty. Set it in Config.ps1 or with NINJA_CLIENT_ID.'
    }
    if ([string]::IsNullOrWhiteSpace($NinjaClientSecret)) {
        throw 'NinjaClientSecret is empty. Set it in Config.ps1 or with NINJA_CLIENT_SECRET.'
    }

    $host = ($TenantDomain.Trim().ToLowerInvariant() -replace '^https?://', '').TrimEnd('/')
    if ([string]::IsNullOrWhiteSpace($host)) {
        throw 'TenantDomain is empty.'
    }

    $authUrl = "https://$host/oauth/authorize"
    $tokenUrl = "https://$host/ws/oauth/token"

    if ($ShowConfigSummary) {
        $maskedClientId = if (Get-Command -Name 'Get-MaskedClientId' -ErrorAction SilentlyContinue) {
            Get-MaskedClientId -ClientId $NinjaClientId
        }
        else {
            $clientId = [string]$NinjaClientId
            if ([string]::IsNullOrWhiteSpace($clientId)) {
                '<empty>'
            }
            elseif ($clientId.Length -le 8) {
                '*' * $clientId.Length
            }
            else {
                '{0}...{1}' -f $clientId.Substring(0, 4), $clientId.Substring($clientId.Length - 4)
            }
        }

        $clientSource = if (Get-Command -Name 'Get-ClientIdSource' -ErrorAction SilentlyContinue) {
            Get-ClientIdSource -ResolvedClientId $NinjaClientId
        }
        else {
            $envClientId = [string]$env:NINJA_CLIENT_ID
            if ([string]::IsNullOrWhiteSpace($envClientId)) {
                'config-file'
            }
            elseif ($envClientId -eq [string]$NinjaClientId) {
                'environment-variable (NINJA_CLIENT_ID)'
            }
            else {
                'config-file (NINJA_CLIENT_ID is set but differs)'
            }
        }

        Write-Host "OAuth config: tenant=$host auth=$authUrl token=$tokenUrl clientId=$maskedClientId source=$clientSource redirect=$NinjaRedirectUri" -ForegroundColor DarkCyan
    }

    $state = New-NinjaOAuthState
    $authorizeUrl = Get-NinjaAuthorizationUrl -ClientId $NinjaClientId -RedirectUri $NinjaRedirectUri -Scopes $NinjaScopes -State $state -AuthorizationEndpoint $authUrl

    Write-Host 'Opening browser for NinjaOne login...' -ForegroundColor Cyan
    $null = Start-NinjaOAuthLogin -AuthorizationUrl $authorizeUrl

    Write-Host "Waiting for callback: $NinjaRedirectUri" -ForegroundColor Yellow
    $callback = Wait-NinjaOAuthCallback -RedirectUri $NinjaRedirectUri -TimeoutSeconds $NinjaCallbackTimeoutSeconds

    if (-not (Test-NinjaOAuthState -ExpectedState $state -ReturnedState $callback.State)) {
        throw 'OAuth state validation failed.'
    }

    $token = Request-NinjaOAuthToken -TokenEndpoint $tokenUrl -ClientId $NinjaClientId -ClientSecret $NinjaClientSecret -Code $callback.Code -RedirectUri $NinjaRedirectUri -TimeoutSeconds $NinjaHttpTimeoutSeconds

    return [pscustomobject]@{
        TenantHost          = $host
        AuthUrl             = $authUrl
        TokenUrl            = $tokenUrl
        ClientId            = $NinjaClientId
        ClientSecret        = $NinjaClientSecret
        HttpTimeoutSeconds  = $NinjaHttpTimeoutSeconds
        Token               = $token
        PathSet             = $pathSet
    }
}

function Invoke-NinjaWebAuthApiGet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Session,
        [Parameter(Mandatory)][string]$PathAndQuery
    )

    if ($PathAndQuery -notmatch '^/') {
        throw 'PathAndQuery must start with /. Example: /v2/organizations'
    }

    $accessToken = Get-ValidNinjaAccessToken -TokenEndpoint $Session.TokenUrl -ClientId $Session.ClientId -ClientSecret $Session.ClientSecret -TimeoutSeconds $Session.HttpTimeoutSeconds
    $uri = "https://$($Session.TenantHost)$PathAndQuery"

    return Invoke-NinjaApiRequest -Method GET -Uri $uri -AccessToken $accessToken -TimeoutSeconds $Session.HttpTimeoutSeconds
}
