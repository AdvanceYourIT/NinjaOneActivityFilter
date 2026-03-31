<#
.SYNOPSIS
    NinjaOne Activity Filter GUI (WPF) using NinjaOne OAuth/API patterns.

.DESCRIPTION
    Standalone NinjaOne Activity Filter GUI for querying, filtering, and exporting activity data.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($PSVersionTable.PSVersion.Major -lt 5) {
    throw 'PowerShell 5.1 or newer is required.'
}


$script:OAuthConfig = $null
$script:OAuthModuleImported = $false

try {
    . (Join-Path $PSScriptRoot 'Config.ps1')
    Import-Module (Join-Path $PSScriptRoot 'NinjaOAuth.psm1') -Force
    $script:OAuthModuleImported = $true
    $script:OAuthConfig = [pscustomobject]@{
        ClientId = $NinjaClientId
        ClientSecret = $NinjaClientSecret
        RedirectUri = $NinjaRedirectUri
        Scopes = $NinjaScopes
        AuthUrl = $NinjaAuthUrl
        TokenUrl = $NinjaTokenUrl
        CallbackTimeoutSeconds = $NinjaCallbackTimeoutSeconds
        HttpTimeoutSeconds = $NinjaHttpTimeoutSeconds
        TokenCachePath = $NinjaTokenCachePath
    }
}
catch {
    throw "Failed to load OAuth module/config from $PSScriptRoot. Error: $($_.Exception.Message)"
}

#region --- Script state ---
$script:TokenInfo        = $null
$script:BaseUrl          = ''
$script:AllResults       = @()
$script:DataTable        = New-Object System.Data.DataTable
$script:DeviceNameCache  = @{}
$script:HostnameDeviceCache = @{}
$script:statusFilters   = @()
$script:Organizations    = @()
$script:MaxPages         = 50
$script:DefaultPageSize  = 1000
$script:IsConnected      = $false
$script:ClientId         = ''
$script:ClientSecret     = ''
#endregion

#region --- Logging ---
function Write-ConsoleLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR','DEBUG')][string]$Level = 'INFO'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $prefix = "[$timestamp][$Level]"

    switch ($Level) {
        'ERROR' { Write-Host "$prefix $Message" -ForegroundColor Red }
        'WARN'  { Write-Host "$prefix $Message" -ForegroundColor Yellow }
        'DEBUG' { Write-Host "$prefix $Message" -ForegroundColor DarkGray }
        default { Write-Host "$prefix $Message" -ForegroundColor Cyan }
    }
}
#endregion

#region --- Helpers (Importer-style API basics) ---
function Normalize-BaseUrl {
    param([AllowNull()][AllowEmptyString()][string]$Url)

    if ([string]::IsNullOrWhiteSpace($Url)) { return '' }

    $normalizedUrl = $Url.Trim()
    $normalizedUrl = $normalizedUrl -replace '^https?://', ''
    $normalizedUrl = $normalizedUrl.TrimEnd('/')
    return $normalizedUrl.ToLowerInvariant()
}

function Get-DomainFromEndpointUrl {
    param([AllowNull()][AllowEmptyString()][string]$Url)

    if ([string]::IsNullOrWhiteSpace($Url)) { return '' }

    try {
        $uri = [Uri]$Url
        return Normalize-BaseUrl -Url $uri.Host
    }
    catch {
        return Normalize-BaseUrl -Url $Url
    }
}

function Get-NinjaEndpointSet {
    param([Parameter(Mandatory = $true)][string]$Domain)

    $normalizedHost = Normalize-BaseUrl -Url $Domain
    if ([string]::IsNullOrWhiteSpace($normalizedHost)) {
        throw 'Domain is empty.'
    }

    # Add or adjust tenant domains here when needed.
    # Known examples: eu.ninjarmm.com, app.ninjarmm.com, ca.ninjarmm.com, oc.ninjarmm.com, us2.ninjarmm.com
    return [pscustomobject]@{
        BaseHost = $normalizedHost
        AuthUrl  = "https://$normalizedHost/oauth/authorize"
        TokenUrl = "https://$normalizedHost/ws/oauth/token"
    }
}


function Save-TokenCacheIfConfigured {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$TokenInfo
    )

    if (-not $script:OAuthConfig -or [string]::IsNullOrWhiteSpace([string]$script:OAuthConfig.TokenCachePath)) {
        return
    }

    try {
        $null = Save-NinjaTokenCache -Path $script:OAuthConfig.TokenCachePath -TokenInfo $TokenInfo
        Write-ConsoleLog -Level DEBUG -Message "Token cache updated at $($script:OAuthConfig.TokenCachePath)"
    }
    catch {
        Write-ConsoleLog -Level WARN -Message "Token cache could not be saved: $($_.Exception.Message)"
    }
}


function ConvertTo-LocalTokenInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$TokenInfo,
        [string]$Source = 'token'
    )

    $expiresInValue = 0
    $rawExpiresIn = [string]$TokenInfo.expires_in
    if (-not [int]::TryParse($rawExpiresIn.Trim(), [ref]$expiresInValue)) {
        throw "Invalid ${Source}: expires_in value '$rawExpiresIn' is not a valid integer."
    }

    $createdAtValue = [datetime]::MinValue
    $rawCreatedAt = [string]$TokenInfo.created_at
    if (-not [datetime]::TryParse($rawCreatedAt.Trim(), [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind, [ref]$createdAtValue)) {
        throw "Invalid ${Source}: created_at value '$rawCreatedAt' is not a valid datetime."
    }

    return [pscustomobject]@{
        access_token  = [string]$TokenInfo.access_token
        refresh_token = [string]$TokenInfo.refresh_token
        expires_in    = $expiresInValue
        created_at    = $createdAtValue
    }
}

function Get-CachedNinjaToken {
    [CmdletBinding()]
    param()

    if (-not $script:OAuthConfig -or [string]::IsNullOrWhiteSpace([string]$script:OAuthConfig.TokenCachePath)) {
        return $null
    }

    if (-not (Test-Path -LiteralPath $script:OAuthConfig.TokenCachePath)) {
        return $null
    }

    try {
        Write-ConsoleLog -Level INFO -Message "Loading token cache from $($script:OAuthConfig.TokenCachePath)"
        $cachedToken = Load-NinjaTokenCache -Path $script:OAuthConfig.TokenCachePath
        $null = Get-ValidNinjaAccessToken -TokenEndpoint $script:OAuthConfig.TokenUrl -ClientId $script:OAuthConfig.ClientId -ClientSecret $script:OAuthConfig.ClientSecret -TimeoutSeconds $script:OAuthConfig.HttpTimeoutSeconds
        $moduleToken = Get-NinjaTokenInfo

        if ($moduleToken) {
            Save-TokenCacheIfConfigured -TokenInfo $moduleToken
            return ConvertTo-LocalTokenInfo -TokenInfo $moduleToken -Source 'module token'
        }

        return ConvertTo-LocalTokenInfo -TokenInfo $cachedToken -Source 'cached token'
    }
    catch {
        Write-ConsoleLog -Level WARN -Message "Cached token is not usable; interactive login required. Error: $($_.Exception.Message)"
        return $null
    }
}

function Get-NinjaToken {
    param(
        [Parameter(Mandatory = $true)][string]$BaseUrl,
        [Parameter(Mandatory = $true)][string]$ClientID,
        [Parameter(Mandatory = $true)][string]$ClientSecret
    )

    if (-not $script:OAuthModuleImported) {
        throw 'OAuth module is not loaded.'
    }

    if ([string]::IsNullOrWhiteSpace($script:OAuthConfig.ClientId) -or [string]::IsNullOrWhiteSpace($script:OAuthConfig.ClientSecret)) {
        throw 'Missing Ninja OAuth client configuration. Fill NinjaClientId and NinjaClientSecret in Config.ps1 or environment variables.'
    }

    $maskedClientId = if (Get-Command -Name 'Get-MaskedClientId' -ErrorAction SilentlyContinue) {
        Get-MaskedClientId -ClientId $script:OAuthConfig.ClientId
    }
    else {
        $clientId = [string]$script:OAuthConfig.ClientId
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

    $clientIdSource = if (Get-Command -Name 'Get-ClientIdSource' -ErrorAction SilentlyContinue) {
        Get-ClientIdSource -ResolvedClientId $script:OAuthConfig.ClientId
    }
    else {
        $envClientId = [string]$env:NINJA_CLIENT_ID
        if ([string]::IsNullOrWhiteSpace($envClientId)) {
            'config-file'
        }
        elseif ($envClientId -eq [string]$script:OAuthConfig.ClientId) {
            'environment-variable (NINJA_CLIENT_ID)'
        }
        else {
            'config-file (NINJA_CLIENT_ID is set but differs)'
        }
    }

    Write-ConsoleLog -Level INFO -Message "OAuth configuration check: tenant=$BaseUrl, clientId=$maskedClientId, source=$clientIdSource, redirect=$($script:OAuthConfig.RedirectUri)"

    $cachedToken = Get-CachedNinjaToken
    if ($cachedToken) {
        Write-ConsoleLog -Level INFO -Message 'Using cached OAuth token. Browser consent is not required for this session.'
        return $cachedToken
    }

    $state = New-NinjaOAuthState
    $authUrl = Get-NinjaAuthorizationUrl -ClientId $script:OAuthConfig.ClientId -RedirectUri $script:OAuthConfig.RedirectUri -Scopes $script:OAuthConfig.Scopes -State $state -AuthorizationEndpoint $script:OAuthConfig.AuthUrl

    Write-ConsoleLog -Level INFO -Message 'Opening browser for NinjaOne web login.'
    $null = Start-NinjaOAuthLogin -AuthorizationUrl $authUrl

    Write-ConsoleLog -Level INFO -Message "Waiting for OAuth callback on $($script:OAuthConfig.RedirectUri)"
    $callback = Wait-NinjaOAuthCallback -RedirectUri $script:OAuthConfig.RedirectUri -TimeoutSeconds $script:OAuthConfig.CallbackTimeoutSeconds

    if (-not (Test-NinjaOAuthState -ExpectedState $state -ReturnedState $callback.State)) {
        throw 'OAuth state validation failed. Please retry login.'
    }

    $token = Request-NinjaOAuthToken -TokenEndpoint $script:OAuthConfig.TokenUrl -ClientId $script:OAuthConfig.ClientId -ClientSecret $script:OAuthConfig.ClientSecret -Code $callback.Code -RedirectUri $script:OAuthConfig.RedirectUri -TimeoutSeconds $script:OAuthConfig.HttpTimeoutSeconds

    Save-TokenCacheIfConfigured -TokenInfo $token

    return ConvertTo-LocalTokenInfo -TokenInfo $token -Source 'oauth token response'
}

function Refresh-NinjaToken {
    param(
        [Parameter(Mandatory = $true)][string]$BaseUrl,
        [Parameter(Mandatory = $true)][string]$ClientID,
        [Parameter(Mandatory = $true)][string]$ClientSecret
    )

    if (-not $script:TokenInfo -or [string]::IsNullOrWhiteSpace([string]$script:TokenInfo.refresh_token)) {
        throw 'No refresh token available. Please login again.'
    }

    $token = Refresh-NinjaOAuthToken -TokenEndpoint $script:OAuthConfig.TokenUrl -ClientId $script:OAuthConfig.ClientId -ClientSecret $script:OAuthConfig.ClientSecret -RefreshToken $script:TokenInfo.refresh_token -TimeoutSeconds $script:OAuthConfig.HttpTimeoutSeconds

    return ConvertTo-LocalTokenInfo -TokenInfo $token -Source 'refresh token response'
}

function Get-AuthHeader {
    if (-not $script:TokenInfo) {
        throw 'Not connected. Please login first.'
    }

    $accessToken = Get-ValidNinjaAccessToken -TokenEndpoint $script:OAuthConfig.TokenUrl -ClientId $script:OAuthConfig.ClientId -ClientSecret $script:OAuthConfig.ClientSecret -TimeoutSeconds $script:OAuthConfig.HttpTimeoutSeconds

    $latestToken = Get-NinjaTokenInfo
    if ($latestToken) {
        Save-TokenCacheIfConfigured -TokenInfo $latestToken
        $normalizedLatestToken = ConvertTo-LocalTokenInfo -TokenInfo $latestToken -Source 'latest module token'
        $script:TokenInfo.refresh_token = [string]$normalizedLatestToken.refresh_token
        $script:TokenInfo.expires_in = $normalizedLatestToken.expires_in
        $script:TokenInfo.created_at = $normalizedLatestToken.created_at
    }

    if ([string]::IsNullOrWhiteSpace($accessToken)) {
        throw 'Unable to obtain a valid access token. Please login again.'
    }

    $script:TokenInfo.access_token = $accessToken
    return @{ Authorization = "Bearer $accessToken" }
}

function Invoke-NinjaApiGet {
    param(
        [Parameter(Mandatory = $true)][string]$Endpoint,
        [hashtable]$Query,
        [Parameter(Mandatory = $true)][string]$ClientID,
        [Parameter(Mandatory = $true)][string]$ClientSecret
    )

    $qs = ''
    if ($Query) {
        $pairs = foreach ($entry in $Query.GetEnumerator()) {
            if (-not [string]::IsNullOrWhiteSpace([string]$entry.Value)) {
                '{0}={1}' -f $entry.Key, [Uri]::EscapeDataString([string]$entry.Value)
            }
        }
        $qs = ($pairs -join '&')
    }

    $uri = "https://$script:BaseUrl$Endpoint"
    if ($qs) { $uri = "$uri`?$qs" }

    try {
        return Invoke-RestMethod -Method Get -Uri $uri -Headers (Get-AuthHeader)
    }
    catch {
        $statusCode = $null
        if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }

        if ($statusCode -eq 401 -or $statusCode -eq 403) {
            Write-ConsoleLog -Level WARN -Message "HTTP $statusCode from API endpoint $Endpoint"
            throw 'Authentication failed. Please click Login again.'
        }

        if ($statusCode -eq 429) {
            throw 'Rate limited by NinjaOne API (HTTP 429). Please retry in a moment.'
        }

        throw "API request failed [$uri]: $($_.Exception.Message)"
    }
}

function Get-ObjectPropertyValue {
    param(
        [Parameter(Mandatory = $true)]$InputObject,
        [Parameter(Mandatory = $true)][string]$PropertyName
    )

    if ($null -eq $InputObject) { return $null }

    $prop = $InputObject.PSObject.Properties[$PropertyName]
    if ($null -eq $prop) { return $null }
    return $prop.Value
}

function ConvertFrom-EpochMs {
    param([AllowNull()]$EpochMs)

    if ($null -eq $EpochMs -or [string]::IsNullOrWhiteSpace([string]$EpochMs)) { return '' }

    try {
        $raw = [long]$EpochMs
        $abs = [math]::Abs($raw)

        if ($abs -lt 100000000000) {
            return [DateTimeOffset]::FromUnixTimeSeconds($raw).LocalDateTime.ToString('yyyy-MM-dd HH:mm:ss')
        }

        return [DateTimeOffset]::FromUnixTimeMilliseconds($raw).LocalDateTime.ToString('yyyy-MM-dd HH:mm:ss')
    }
    catch {
        return [string]$EpochMs
    }
}

function Get-ActivityDetails {
    param([Parameter(Mandatory = $true)]$Activity)

    $directCandidates = @(
        'scriptName','script','scriptDisplayName','actionName','name','title','subject',
        'description','message','result','resultMessage','statusMessage','errorMessage'
    )

    foreach ($candidate in $directCandidates) {
        $value = [string](Get-ObjectPropertyValue -InputObject $Activity -PropertyName $candidate)
        if (-not [string]::IsNullOrWhiteSpace($value)) { return (Normalize-DetailsText -Text $value) }
    }

    $metadata = Get-ObjectPropertyValue -InputObject $Activity -PropertyName 'metadata'
    if ($metadata) {
        foreach ($candidate in @('scriptName','name','title','message','result','description')) {
            $value = [string](Get-ObjectPropertyValue -InputObject $metadata -PropertyName $candidate)
            if (-not [string]::IsNullOrWhiteSpace($value)) { return (Normalize-DetailsText -Text $value) }
        }
    }

    return ''
}

function Normalize-DetailsText {
    param([AllowNull()][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }

    $singleLine = ($Text -replace '[\r\n]+', ' ' -replace '\s{2,}', ' ').Trim()
    return $singleLine
}

function Resolve-DeviceHostname {
    param(
        [AllowNull()]$DeviceId,
        [Parameter(Mandatory = $true)][string]$ClientID,
        [Parameter(Mandatory = $true)][string]$ClientSecret
    )

    $id = [string]$DeviceId
    if ([string]::IsNullOrWhiteSpace($id)) { return '' }

    if ($script:DeviceNameCache.ContainsKey($id)) {
        return [string]$script:DeviceNameCache[$id]
    }

    $hostname = ''
    try {
        $device = Invoke-NinjaApiGet -Endpoint "/v2/device/$id" -ClientID $ClientID -ClientSecret $ClientSecret
        foreach ($candidate in @('systemName','hostname','deviceName','displayName','name','dnsName')) {
            $value = [string](Get-ObjectPropertyValue -InputObject $device -PropertyName $candidate)
            if (-not [string]::IsNullOrWhiteSpace($value)) {
                $hostname = $value
                break
            }
        }
    }
    catch {
        Write-ConsoleLog -Level DEBUG -Message "Device hostname lookup failed for deviceId=${id}: $($_.Exception.Message)"
    }

    $script:DeviceNameCache[$id] = $hostname
    if (-not [string]::IsNullOrWhiteSpace($hostname)) {
        $script:HostnameDeviceCache[$hostname.ToLowerInvariant()] = $id
    }
    return $hostname
}

function Resolve-DeviceIdByHostname {
    param(
        [AllowNull()][string]$Hostname,
        [Parameter(Mandatory = $true)][string]$ClientID,
        [Parameter(Mandatory = $true)][string]$ClientSecret
    )

    if ([string]::IsNullOrWhiteSpace($Hostname)) { return '' }

    $needle = $Hostname.Trim().ToLowerInvariant()
    if ($script:HostnameDeviceCache.ContainsKey($needle)) {
        return [string]$script:HostnameDeviceCache[$needle]
    }

    $pageSize = 2000
    $maxDevicePages = if ($script:MaxPages -gt 0) { [int]$script:MaxPages } else { 50 }
    $olderThan = $null
    $pageCount = 0

    do {
        $query = @{ pageSize = [string]$pageSize }
        if ($olderThan) { $query.olderThan = [string]$olderThan }

        Write-ConsoleLog -Level DEBUG -Message "GET /v2/devices page=$($pageCount + 1) lookup='$Hostname'"
        $resp = Invoke-NinjaApiGet -Endpoint '/v2/devices' -Query $query -ClientID $ClientID -ClientSecret $ClientSecret

        $devices = @()
        if ($resp -is [System.Array]) {
            $devices = @($resp)
        }
        else {
            foreach ($prop in @('devices','results','items','data')) {
                $candidate = Get-ObjectPropertyValue -InputObject $resp -PropertyName $prop
                if ($candidate) {
                    $devices = @($candidate)
                    break
                }
            }
        }

        if (-not $devices -or $devices.Count -eq 0) { break }

        foreach ($d in $devices) {
            $id = [string](Get-ObjectPropertyValue -InputObject $d -PropertyName 'id')
            if ([string]::IsNullOrWhiteSpace($id)) { continue }

            foreach ($nameProp in @('systemName','hostname','deviceName','displayName','name','dnsName')) {
                $name = [string](Get-ObjectPropertyValue -InputObject $d -PropertyName $nameProp)
                if ([string]::IsNullOrWhiteSpace($name)) { continue }

                $normalizedName = $name.Trim().ToLowerInvariant()
                if ($normalizedName -eq $needle) {
                    $script:HostnameDeviceCache[$needle] = $id
                    $script:HostnameDeviceCache[$normalizedName] = $id
                    $script:DeviceNameCache[$id] = $name
                    return $id
                }
            }
        }

        $pageCount++
        if ($devices.Count -ge $pageSize) {
            $olderThan = ($devices | Measure-Object -Property id -Minimum).Minimum
        }
        else {
            $olderThan = $null
        }
    } while ($olderThan -and $pageCount -lt $maxDevicePages)

    if ($olderThan -and $pageCount -ge $maxDevicePages) {
        Write-ConsoleLog -Level WARN -Message "Device hostname lookup for '$Hostname' stopped after $maxDevicePages pages (guard hit); results may be truncated."
    }

    return ''
}

function Convert-EpochToLocalDateTime {
    param([AllowNull()]$Epoch)

    if ($null -eq $Epoch -or [string]::IsNullOrWhiteSpace([string]$Epoch)) { return $null }

    try {
        $raw = [long]$Epoch
        $abs = [math]::Abs($raw)

        if ($abs -lt 100000000000) {
            return [DateTimeOffset]::FromUnixTimeSeconds($raw).LocalDateTime
        }

        return [DateTimeOffset]::FromUnixTimeMilliseconds($raw).LocalDateTime
    }
    catch {
        return $null
    }
}

function Apply-DateFilterToActivities {
    param(
        [AllowNull()][object[]]$Activities,
        [AllowNull()][string]$After,
        [AllowNull()][string]$Before
    )

    if ($null -eq $Activities -or $Activities.Count -eq 0) {
        return @()
    }

    $acceptedFormats = @('yyyy-MM-dd HH:mm', 'yyyy-MM-dd')

    $afterBoundary = $null
    if (-not [string]::IsNullOrWhiteSpace($After)) {
        $afterBoundary = Parse-DateFilterValue -Value $After
    }

    $beforeBoundary = $null
    if (-not [string]::IsNullOrWhiteSpace($Before)) {
        $beforeBoundary = Parse-DateFilterValue -Value $Before
    }

    $filtered = foreach ($a in $Activities) {
        $activityTimeEpoch = Get-ObjectPropertyValue -InputObject $a -PropertyName 'activityTime'
        $activityTimeLocal = Convert-EpochToLocalDateTime -Epoch $activityTimeEpoch

        if ($null -eq $activityTimeLocal) {
            continue
        }

        if ($afterBoundary -and $activityTimeLocal -lt $afterBoundary) {
            continue
        }

        if ($beforeBoundary -and $activityTimeLocal -ge $beforeBoundary) {
            continue
        }

        $a
    }

    return @($filtered)
}

function Parse-DateFilterValue {
    param([Parameter(Mandatory = $true)][string]$Value)

    $trimmed = $Value.Trim()
    foreach ($fmt in @('yyyy-MM-dd HH:mm', 'yyyy-MM-dd')) {
        try {
            return [datetime]::ParseExact($trimmed, $fmt, [System.Globalization.CultureInfo]::InvariantCulture)
        }
        catch { }
    }

    throw "Date/time value '$Value' is not in a supported format."
}

function Get-DateTimeFilterString {
    param(
        [AllowNull()][datetime]$Date,
        [AllowNull()][string]$TimeText,
        [string]$DefaultTime = '00:00'
    )

    if ($null -eq $Date) { return '' }

    $timePart = if ([string]::IsNullOrWhiteSpace($TimeText)) { $DefaultTime } else { $TimeText.Trim() }
    $combined = '{0:yyyy-MM-dd} {1}' -f $Date, $timePart

    try {
        $parsed = [datetime]::ParseExact($combined, 'yyyy-MM-dd HH:mm', [System.Globalization.CultureInfo]::InvariantCulture)
    }
    catch {
        throw "Invalid time '$timePart'. Use HH:mm format (e.g. 09:30)."
    }

    return $parsed.ToString('yyyy-MM-dd HH:mm')
}

function Convert-DateFilterToApiDate {
    param(
        [AllowNull()][string]$Value,
        [switch]$IsBefore
    )

    if ([string]::IsNullOrWhiteSpace($Value)) { return '' }

    $trimmed = $Value.Trim()

    # Fast path: keep only date component when datetime is provided.
    if ($trimmed -match '^(\d{4}-\d{2}-\d{2})') {
        $datePart = [datetime]::ParseExact($Matches[1], 'yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture)
        if ($IsBefore) { $datePart = $datePart.AddDays(1) }
        return $datePart.ToString('yyyy-MM-dd')
    }

    try {
        $parsed = Parse-DateFilterValue -Value $trimmed
        if ($IsBefore) { $parsed = $parsed.Date.AddDays(1) }
        return $parsed.ToString('yyyy-MM-dd')
    }
    catch {
        # Last fallback: attempt generic parse; if that fails, remove any time suffix.
        try {
            $parsed = [datetime]$trimmed
            if ($IsBefore) { $parsed = $parsed.Date.AddDays(1) }
            return $parsed.ToString('yyyy-MM-dd')
        }
        catch {
            $fallbackDate = ($trimmed -split '\s+', 2)[0]
            if ($IsBefore) {
                try {
                    return ([datetime]::ParseExact($fallbackDate, 'yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture).AddDays(1)).ToString('yyyy-MM-dd')
                }
                catch { }
            }
            return $fallbackDate
        }
    }
}

function Get-Activities {
    param(
        [string[]]$Types,
        [string]$After,
        [string]$Before,
        [string]$DeviceId,
        [AllowNull()][string]$OrganizationId,
        [string]$ClientID,
        [string]$ClientSecret
    )

    $allActivities = @()
    # Compatibility guard: older downloaded variants referenced $statusFilters in this function.
    $script:statusFilters = @($null)
    $apiAfter = Convert-DateFilterToApiDate -Value $After
    $apiBefore = Convert-DateFilterToApiDate -Value $Before -IsBefore
    $baseQuery = @{ pageSize = [string]$script:DefaultPageSize; after = $apiAfter; before = $apiBefore }
    $organizationFilter = $null
    if (-not [string]::IsNullOrWhiteSpace([string]$OrganizationId)) {
        # /v2/activities does not expose direct organizationId parameter in this API spec revision.
        # Use device filter (df) to scope by organization.
        $organizationFilter = "organizationId = $([string]$OrganizationId)"
        Write-ConsoleLog -Level DEBUG -Message "Organization filter prepared via df: $organizationFilter"
    }

    $endpoints = @()
    if ($DeviceId -match '^\d+$') {
        foreach ($type in $Types) {
            foreach ($status in $statusFilters) {
                $q = $baseQuery.Clone()
                $q.activityType = $type
                if ($status) { $q.status = $status }
                $endpoints += [pscustomobject]@{ Endpoint = "/v2/device/$DeviceId/activities"; Query = $q }
            }
        }
    }
    elseif (-not [string]::IsNullOrWhiteSpace([string]$OrganizationId)) {
        $organizationDeviceIds = Get-OrganizationDeviceIds -OrganizationId $OrganizationId -ClientID $ClientID -ClientSecret $ClientSecret
        if (@($organizationDeviceIds).Count -eq 0) {
            Write-ConsoleLog -Level WARN -Message "No devices found for organizationId=$OrganizationId."
            return @()
        }

        Write-ConsoleLog -Level INFO -Message "OrganizationId=$OrganizationId resolved to $(@($organizationDeviceIds).Count) device(s). Querying device activity endpoints."
        foreach ($deviceIdValue in @($organizationDeviceIds)) {
            foreach ($type in $Types) {
                foreach ($status in $statusFilters) {
                    $q = $baseQuery.Clone()
                    $q.activityType = $type
                    if ($status) { $q.status = $status }
                    $endpoints += [pscustomobject]@{ Endpoint = "/v2/device/$deviceIdValue/activities"; Query = $q }
                }
            }
        }
    }
    else {
        foreach ($type in $Types) {
            $q = $baseQuery.Clone()
            $q.type = $type
            if (-not [string]::IsNullOrWhiteSpace([string]$organizationFilter)) {
                $q.df = $organizationFilter
            }
            $endpoints += [pscustomobject]@{ Endpoint = '/v2/activities'; Query = $q }
        }
    }

    foreach ($ep in $endpoints) {
        $olderThan = $null
        $pageCount = 0

        do {
            $q = $ep.Query.Clone()
            if ($olderThan) { $q.olderThan = [string]$olderThan }

            $typeContext = if ($q.ContainsKey('type')) { [string]$q.type } elseif ($q.ContainsKey('activityType')) { [string]$q.activityType } else { '(none)' }
            Write-ConsoleLog -Level DEBUG -Message "GET $($ep.Endpoint) page=$($pageCount + 1) type=$typeContext"
            try {
                $resp = Invoke-NinjaApiGet -Endpoint $ep.Endpoint -Query $q -ClientID $ClientID -ClientSecret $ClientSecret
            }
            catch {
                Write-ConsoleLog -Level WARN -Message "Skipping failed query for activity type '$typeContext': $($_.Exception.Message)"
                break
            }

            $activities = @($resp.activities)
            if (-not $activities -or $activities.Count -eq 0) { break }

            $allActivities += $activities
            $pageCount++

            if ($activities.Count -ge $script:DefaultPageSize) {
                $olderThan = ($activities | Measure-Object -Property id -Minimum).Minimum
            }
            else {
                $olderThan = $null
            }

        } while ($olderThan -and $pageCount -lt $script:MaxPages)
    }

    $uniqueActivities = @($allActivities | Sort-Object -Property id -Unique)
    if ($uniqueActivities.Count -eq 0) { return @() }

    $dateFilteredActivities = Apply-DateFilterToActivities -Activities $uniqueActivities -After $After -Before $Before
    return @($dateFilteredActivities)
}

function Get-OrganizationDeviceIds {
    param(
        [Parameter(Mandatory = $true)][string]$OrganizationId,
        [Parameter(Mandatory = $true)][string]$ClientID,
        [Parameter(Mandatory = $true)][string]$ClientSecret
    )

    $allDeviceIds = @()
    $olderThan = $null
    $pageSize = 1000
    $pageCount = 0

    do {
        $query = @{ pageSize = [string]$pageSize }
        if (-not [string]::IsNullOrWhiteSpace([string]$olderThan)) {
            $query.olderThan = [string]$olderThan
        }

        $resp = Invoke-NinjaApiGet -Endpoint '/v2/devices' -Query $query -ClientID $ClientID -ClientSecret $ClientSecret
        $devices = @()
        if ($resp -is [System.Array]) {
            $devices = @($resp)
        }
        else {
            foreach ($prop in @('devices','results','items','data')) {
                $candidate = Get-ObjectPropertyValue -InputObject $resp -PropertyName $prop
                if ($candidate) {
                    $devices = @($candidate)
                    break
                }
            }
        }

        if (@($devices).Count -eq 0) { break }

        foreach ($device in @($devices)) {
            $id = [string](Get-ObjectPropertyValue -InputObject $device -PropertyName 'id')
            if ([string]::IsNullOrWhiteSpace($id)) { continue }

            $deviceOrg = [string](Get-ObjectPropertyValue -InputObject $device -PropertyName 'organizationId')
            if ([string]::IsNullOrWhiteSpace($deviceOrg)) {
                $deviceOrg = [string](Get-ObjectPropertyValue -InputObject $device -PropertyName 'orgId')
            }
            if ([string]::IsNullOrWhiteSpace($deviceOrg)) {
                $orgObj = Get-ObjectPropertyValue -InputObject $device -PropertyName 'organization'
                if ($orgObj) {
                    $deviceOrg = [string](Get-ObjectPropertyValue -InputObject $orgObj -PropertyName 'id')
                }
            }

            if ($deviceOrg -eq [string]$OrganizationId) {
                $allDeviceIds += $id
            }
        }

        $pageCount++
        if (@($devices).Count -ge $pageSize) {
            $olderThan = [string](($devices | Measure-Object -Property id -Minimum).Minimum)
        }
        else {
            $olderThan = $null
        }
    } while (-not [string]::IsNullOrWhiteSpace([string]$olderThan) -and $pageCount -lt $script:MaxPages)

    return @($allDeviceIds | Sort-Object -Unique)
}

function Get-Organizations {
    param(
        [Parameter(Mandatory = $true)][string]$ClientID,
        [Parameter(Mandatory = $true)][string]$ClientSecret
    )

    $allOrganizations = @()
    $after = $null
    $pageSize = 200

    do {
        $query = @{ pageSize = [string]$pageSize }
        if (-not [string]::IsNullOrWhiteSpace([string]$after)) {
            $query.after = [string]$after
        }

        $response = Invoke-NinjaApiGet -Endpoint '/v2/organizations' -Query $query -ClientID $ClientID -ClientSecret $ClientSecret
        $pageItems = @()

        if ($response -is [System.Array]) {
            $pageItems = @($response)
        }
        elseif ($response) {
            foreach ($candidate in @('organizations','items','results','data')) {
                $candidateItems = Get-ObjectPropertyValue -InputObject $response -PropertyName $candidate
                if ($candidateItems) {
                    $pageItems = @($candidateItems)
                    break
                }
            }

            if ($pageItems.Count -eq 0) {
                $pageItems = @($response)
            }
        }

        if ($pageItems.Count -eq 0) { break }

        foreach ($organization in $pageItems) {
            $id = Get-ObjectPropertyValue -InputObject $organization -PropertyName 'id'
            $name = Get-ObjectPropertyValue -InputObject $organization -PropertyName 'name'
            if ($null -ne $id -and -not [string]::IsNullOrWhiteSpace([string]$name)) {
                $allOrganizations += [pscustomobject]@{
                    id   = [string]$id
                    name = [string]$name
                }
            }
        }

        $nextAfter = $null
        foreach ($candidate in @('after','nextAfter','nextCursor','cursor')) {
            $value = Get-ObjectPropertyValue -InputObject $response -PropertyName $candidate
            if (-not [string]::IsNullOrWhiteSpace([string]$value)) {
                $nextAfter = [string]$value
                break
            }
        }

        if ([string]::IsNullOrWhiteSpace($nextAfter)) {
            $last = $pageItems[-1]
            if ($last) {
                $lastId = Get-ObjectPropertyValue -InputObject $last -PropertyName 'id'
                if ($null -ne $lastId -and $pageItems.Count -ge $pageSize) {
                    $nextAfter = [string]$lastId
                }
            }
        }

        $after = $nextAfter
    } while (-not [string]::IsNullOrWhiteSpace([string]$after))

    $script:Organizations = @($allOrganizations | Sort-Object -Property name, id -Unique)
    return @(
        [pscustomobject]@{
            DisplayName = 'All organizations'
            Id          = $null
        }
    ) + @(
        $script:Organizations | ForEach-Object {
            [pscustomobject]@{
                DisplayName = $_.name
                Id          = $_.id
            }
        }
    )
}
#endregion

#region --- WPF/XAML setup (Importer-style) ---
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase
Add-Type -AssemblyName System.Windows.Forms

[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="NinjaOne Activity Filter"
        Height="760"
        Width="1220"
        MinHeight="620"
        MinWidth="980"
        WindowStartupLocation="CenterScreen"
        Background="#0F172A">
    <Window.Resources>
        <SolidColorBrush x:Key="PanelBg" Color="#0F172A"/>
        <SolidColorBrush x:Key="CardBg" Color="#1E293B"/>
        <SolidColorBrush x:Key="Accent" Color="#6366F1"/>
        <SolidColorBrush x:Key="InputBg" Color="#0B1220"/>
        <SolidColorBrush x:Key="TextPrimary" Color="#E2E8F0"/>
        <SolidColorBrush x:Key="TextMuted" Color="#94A3B8"/>

        <Style TargetType="TextBlock">
            <Setter Property="Foreground" Value="{StaticResource TextPrimary}"/>
            <Setter Property="FontFamily" Value="Segoe UI"/>
        </Style>
        <Style TargetType="TextBox">
            <Setter Property="Background" Value="{StaticResource InputBg}"/>
            <Setter Property="Foreground" Value="White"/>
            <Setter Property="BorderBrush" Value="#334155"/>
            <Setter Property="Padding" Value="6,4"/>
        </Style>
        <Style TargetType="PasswordBox">
            <Setter Property="Background" Value="{StaticResource InputBg}"/>
            <Setter Property="Foreground" Value="White"/>
            <Setter Property="BorderBrush" Value="#334155"/>
            <Setter Property="Padding" Value="6,4"/>
        </Style>
        <Style TargetType="DatePicker">
            <Setter Property="Background" Value="{StaticResource InputBg}"/>
            <Setter Property="Foreground" Value="White"/>
        </Style>
        <Style TargetType="DatePickerTextBox">
            <Setter Property="Background" Value="{StaticResource InputBg}"/>
            <Setter Property="Foreground" Value="White"/>
            <Setter Property="BorderBrush" Value="#334155"/>
            <Setter Property="CaretBrush" Value="White"/>
        </Style>
        <Style TargetType="ListBox">
            <Setter Property="Background" Value="{StaticResource InputBg}"/>
            <Setter Property="Foreground" Value="White"/>
            <Setter Property="BorderBrush" Value="#334155"/>
        </Style>
        <Style TargetType="Button">
            <Setter Property="Background" Value="{StaticResource Accent}"/>
            <Setter Property="Foreground" Value="White"/>
            <Setter Property="BorderBrush" Value="#4F46E5"/>
            <Setter Property="Padding" Value="10,4"/>
            <Setter Property="Cursor" Value="Hand"/>
        </Style>
    </Window.Resources>

    <Grid Margin="12">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <Border Grid.Row="0" Background="{StaticResource CardBg}" CornerRadius="8" Padding="10" Margin="0,0,0,10">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="190"/>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="220"/>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="220"/>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="140"/>
                </Grid.ColumnDefinitions>

                <TextBlock Grid.Column="0" Text="Domain:" VerticalAlignment="Center" Margin="0,0,8,0"/>
                <ComboBox Grid.Column="1" x:Name="cmbDomain" Height="26" IsEditable="False"/>
                <TextBlock Grid.Column="2" Text="Web OAuth:" VerticalAlignment="Center" Margin="12,0,8,0"/>
                <TextBlock Grid.Column="3" Text="Use Config.ps1 credentials" VerticalAlignment="Center" Foreground="{StaticResource TextMuted}"/>
                <TextBlock Grid.Column="4" Text="" VerticalAlignment="Center" Margin="12,0,8,0"/>
                <TextBlock Grid.Column="5" Text="Browser login + callback" VerticalAlignment="Center" Foreground="{StaticResource TextMuted}"/>
                <Button Grid.Column="6" x:Name="btnConnect" Content="Login" Height="26" Width="100" Margin="12,0,0,0"/>
                <TextBlock Grid.Column="7" x:Name="lblConnStatus" Foreground="{StaticResource TextMuted}" VerticalAlignment="Center" Margin="12,0,0,0" Text="Disconnected"/>
            </Grid>
        </Border>

        <Border Grid.Row="1" Background="{StaticResource CardBg}" CornerRadius="8" Padding="10" Margin="0,0,0,10">
            <Grid>
                <Grid.RowDefinitions>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="Auto"/>
                </Grid.RowDefinitions>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="130"/>
                    <ColumnDefinition Width="70"/>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="130"/>
                    <ColumnDefinition Width="70"/>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="220"/>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="220"/>
                    <ColumnDefinition Width="*"/>
                </Grid.ColumnDefinitions>

                <TextBlock Grid.Row="0" Grid.Column="0" Text="After:" VerticalAlignment="Center" Margin="0,0,8,8"/>
                <DatePicker Grid.Row="0" Grid.Column="1" x:Name="dpAfter" Margin="0,0,8,8"/>
                <TextBox Grid.Row="0" Grid.Column="2" x:Name="txtAfterTime" Height="24" Text="00:00" ToolTip="HH:mm" Margin="0,0,12,8"/>
                <TextBlock Grid.Row="0" Grid.Column="3" Text="Before:" VerticalAlignment="Center" Margin="0,0,8,8"/>
                <DatePicker Grid.Row="0" Grid.Column="4" x:Name="dpBefore" Margin="0,0,8,8"/>
                <TextBox Grid.Row="0" Grid.Column="5" x:Name="txtBeforeTime" Height="24" Text="00:00" ToolTip="HH:mm" Margin="0,0,12,8"/>
                <TextBlock Grid.Row="0" Grid.Column="6" Text="Device ID / Hostname (optional):" VerticalAlignment="Center" Margin="0,0,8,8"/>
                <TextBox Grid.Row="0" Grid.Column="7" x:Name="txtDeviceId" Height="24" Margin="0,0,12,8"/>
                <TextBlock Grid.Row="0" Grid.Column="8" Text="Organization (optional):" VerticalAlignment="Center" Margin="0,0,8,8"/>
                <ComboBox Grid.Row="0" Grid.Column="9" x:Name="cmbOrganization" Height="24" Margin="0,0,12,8"/>

                <Grid Grid.Row="1" Grid.ColumnSpan="11" Margin="0,8,0,0">
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="2*"/>
                        <ColumnDefinition Width="260"/>
                    </Grid.ColumnDefinitions>

                    <StackPanel Grid.Column="0" Margin="0,0,10,0">
                        <TextBlock Text="Activity Types" FontWeight="SemiBold" Margin="0,0,0,4"/>
                        <StackPanel Orientation="Horizontal" Margin="0,0,0,6">
                            <Button x:Name="btnSelectAllTypes" Content="Select all" Height="24" Width="90" Margin="0,0,8,0"/>
                            <Button x:Name="btnDeselectAllTypes" Content="Deselect all" Height="24" Width="90"/>
                        </StackPanel>
                        <ListBox x:Name="lstTypes" SelectionMode="Multiple" Height="220" MinHeight="220"/>
                    </StackPanel>

                    <StackPanel Grid.Column="1">
                        <Button x:Name="btnSearch" Content="Search" Height="28" Width="110" HorizontalAlignment="Left" IsEnabled="False" Margin="0,0,0,8"/>
                        <TextBlock x:Name="lblCount" Text="No results" Foreground="{StaticResource TextMuted}" Margin="0,20,0,6"/>
                        <TextBlock x:Name="lblStatus" Text="Ready. Click Login to authenticate with NinjaOne web OAuth." Foreground="{StaticResource TextPrimary}" TextWrapping="Wrap"/>
                    </StackPanel>
                </Grid>
            </Grid>
        </Border>

        <DataGrid Grid.Row="2" x:Name="dataGridView" AutoGenerateColumns="False" IsReadOnly="True" CanUserAddRows="False" Margin="0,0,0,10" Background="#111827" Foreground="#E2E8F0" BorderBrush="#334155" RowBackground="#0F172A" AlternatingRowBackground="#111827" GridLinesVisibility="Horizontal" HeadersVisibility="Column" ScrollViewer.HorizontalScrollBarVisibility="Auto" ScrollViewer.VerticalScrollBarVisibility="Auto" FrozenColumnCount="5">
            <DataGrid.ColumnHeaderStyle>
                <Style TargetType="DataGridColumnHeader">
                    <Setter Property="Background" Value="#1F2937"/>
                    <Setter Property="Foreground" Value="#F8FAFC"/>
                    <Setter Property="BorderBrush" Value="#334155"/>
                    <Setter Property="FontWeight" Value="SemiBold"/>
                </Style>
            </DataGrid.ColumnHeaderStyle>
            <DataGrid.Columns>
                <DataGridTextColumn Header="Activity ID" Binding="{Binding id}" Width="100"/>
                <DataGridTextColumn Header="Activity Time" Binding="{Binding activityTime}" Width="170"/>
                <DataGridTextColumn Header="Device ID" Binding="{Binding deviceId}" Width="100"/>
                <DataGridTextColumn Header="Hostname" Binding="{Binding hostname}" Width="180"/>
                <DataGridTextColumn Header="Type" Binding="{Binding activityType}" Width="180"/>
                <DataGridTextColumn Header="Status" Binding="{Binding statusCode}" Width="160"/>
                <DataGridTextColumn Header="Severity" Binding="{Binding severity}" Width="120"/>
                <DataGridTemplateColumn Header="Details" Width="Auto" MinWidth="520">
                    <DataGridTemplateColumn.CellTemplate>
                        <DataTemplate>
                            <TextBlock Text="{Binding details}" ToolTip="{Binding details}" TextTrimming="CharacterEllipsis"/>
                        </DataTemplate>
                    </DataGridTemplateColumn.CellTemplate>
                </DataGridTemplateColumn>
            </DataGrid.Columns>
        </DataGrid>

        <DockPanel Grid.Row="3" LastChildFill="False">
            <Button x:Name="btnExport" Content="Export CSV" Width="110" Height="28" Margin="0,0,8,0" IsEnabled="False"/>
            <Button x:Name="btnCopy" Content="Copy Rows" Width="110" Height="28" IsEnabled="False"/>
        </DockPanel>
    </Grid>
</Window>
"@

$reader = [System.Xml.XmlReader]::Create([System.IO.StringReader]::new($xaml.OuterXml))
$window = [Windows.Markup.XamlReader]::Load($reader)

$cmbDomain     = $window.FindName('cmbDomain')
$btnConnect    = $window.FindName('btnConnect')
$lblConnStatus = $window.FindName('lblConnStatus')
$dpAfter       = $window.FindName('dpAfter')
$dpBefore      = $window.FindName('dpBefore')
$txtAfterTime  = $window.FindName('txtAfterTime')
$txtBeforeTime = $window.FindName('txtBeforeTime')
$txtDeviceId   = $window.FindName('txtDeviceId')
$cmbOrganization = $window.FindName('cmbOrganization')
$btnSearch     = $window.FindName('btnSearch')
$lstTypes      = $window.FindName('lstTypes')
$btnSelectAllTypes = $window.FindName('btnSelectAllTypes')
$btnDeselectAllTypes = $window.FindName('btnDeselectAllTypes')
$lblCount      = $window.FindName('lblCount')
$lblStatus     = $window.FindName('lblStatus')
$dataGridView  = $window.FindName('dataGridView')
$btnExport     = $window.FindName('btnExport')
$btnCopy       = $window.FindName('btnCopy')
#endregion

#region --- UI data setup ---
$dpAfter.SelectedDate = (Get-Date).AddDays(-7)
$dpBefore.SelectedDate = (Get-Date).AddDays(1)
$txtAfterTime.Text = '00:00'
$txtBeforeTime.Text = '00:00'

$supportedDomains = @('eu.ninjarmm.com','app.ninjarmm.com','ca.ninjarmm.com','oc.ninjarmm.com','us2.ninjarmm.com')
$cmbDomain.ItemsSource = $supportedDomains

$defaultDomain = Get-DomainFromEndpointUrl -Url $script:OAuthConfig.AuthUrl
if ([string]::IsNullOrWhiteSpace($defaultDomain) -or ($supportedDomains -notcontains $defaultDomain)) {
    $defaultDomain = 'eu.ninjarmm.com'
}
$cmbDomain.SelectedItem = $defaultDomain

$activityTypes = @('ACTIONSET','ACTION','CONDITION','CONDITION_ACTIONSET','CONDITION_ACTION','ANTIVIRUS','PATCH_MANAGEMENT','TEAMVIEWER','MONITOR','SYSTEM','COMMENT','SHADOWPROTECT','IMAGEMANAGER','HELP_REQUEST','SOFTWARE_PATCH_MANAGEMENT','SPLASHTOP','CLOUDBERRY','CLOUDBERRY_BACKUP','SCHEDULED_TASK','RDP','SCRIPTING','SECURITY','REMOTE_TOOLS','VIRTUALIZATION','PSA','MDM','NINJA_REMOTE','NINJA_QUICK_CONNECT','NINJA_NETWORK_DISCOVERY','NINJA_BACKUP','NINJA_TICKETING','KNOWLEDGE_BASE','RELATED_ITEM','CLIENT_CHECKLIST','CHECKLIST_TEMPLATE','DOCUMENTATION','MICROSOFT_INTUNE','DYNAMIC_POLICY')
$lstTypes.ItemsSource = $activityTypes
$lstTypes.SelectedItems.Add('SCRIPTING') | Out-Null
$cmbOrganization.ItemsSource = @([pscustomobject]@{ DisplayName = 'All organizations'; Id = $null })
$cmbOrganization.DisplayMemberPath = 'DisplayName'
$cmbOrganization.SelectedValuePath = 'Id'
$cmbOrganization.SelectedIndex = 0

foreach ($colName in @('id','activityTime','deviceId','hostname','activityType','statusCode','severity','details')) {
    [void]$script:DataTable.Columns.Add($colName)
}
$dataGridView.ItemsSource = $script:DataTable.DefaultView
#endregion

function Set-ConnectionUiState {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][bool]$Connected)

    $script:IsConnected = $Connected

    if ($Connected) {
        $btnConnect.Content = 'Disconnect'
        $lblConnStatus.Text = 'Connected'
        $lblConnStatus.Foreground = [System.Windows.Media.Brushes]::LimeGreen
        $btnSearch.IsEnabled = $true
        return
    }

    $btnConnect.Content = 'Login'
    $lblConnStatus.Text = 'Disconnected'
    $lblConnStatus.Foreground = [System.Windows.Media.Brushes]::DarkGray
    $btnSearch.IsEnabled = $false
}

Set-ConnectionUiState -Connected $false

function Disconnect-NinjaSession {
    [CmdletBinding()]
    param()

    $script:TokenInfo = $null
    $script:BaseUrl = ''
    $script:DeviceNameCache = @{}
    $script:HostnameDeviceCache = @{}
    $script:Organizations = @()
    $script:ClientId = ''
    $script:ClientSecret = ''
    $cmbOrganization.ItemsSource = @([pscustomobject]@{ DisplayName = 'All organizations'; Id = $null })
    $cmbOrganization.DisplayMemberPath = 'DisplayName'
    $cmbOrganization.SelectedValuePath = 'Id'
    $cmbOrganization.SelectedIndex = 0

    Set-ConnectionUiState -Connected $false
    $lblStatus.Text = 'Disconnected.'
    Write-ConsoleLog -Level INFO -Message 'Disconnected from NinjaOne session.'
}

#region --- Event handlers ---
$btnConnect.Add_Click({
    if ($script:IsConnected) {
        Disconnect-NinjaSession
        return
    }

    $domain = [string]$cmbDomain.SelectedItem
    if ([string]::IsNullOrWhiteSpace($domain)) {
        [System.Windows.MessageBox]::Show('Please select a domain.', 'Missing Fields', 'OK', 'Warning') | Out-Null
        return
    }

    Write-ConsoleLog -Level INFO -Message "Connecting to NinjaOne tenant $domain"

    try {
        $endpointSet = Get-NinjaEndpointSet -Domain $domain
        $script:BaseUrl = $endpointSet.BaseHost
        $script:OAuthConfig.AuthUrl = $endpointSet.AuthUrl
        $script:OAuthConfig.TokenUrl = $endpointSet.TokenUrl
        $script:TokenInfo = Get-NinjaToken -BaseUrl $script:BaseUrl -ClientID $script:OAuthConfig.ClientId -ClientSecret $script:OAuthConfig.ClientSecret
        $script:DeviceNameCache = @{}
        $script:HostnameDeviceCache = @{}
        $script:Organizations = @()
        $script:ClientId = [string]$script:OAuthConfig.ClientId
        $script:ClientSecret = [string]$script:OAuthConfig.ClientSecret

        try {
            $organizationOptions = Get-Organizations -ClientID $script:ClientId -ClientSecret $script:ClientSecret
            $cmbOrganization.ItemsSource = $organizationOptions
            $cmbOrganization.DisplayMemberPath = 'DisplayName'
            $cmbOrganization.SelectedValuePath = 'Id'
            $cmbOrganization.SelectedIndex = 0
            Write-ConsoleLog -Level INFO -Message "Loaded $($script:Organizations.Count) organizations."
        }
        catch {
            $script:Organizations = @()
            $cmbOrganization.ItemsSource = @([pscustomobject]@{ DisplayName = 'All organizations'; Id = $null })
            $cmbOrganization.DisplayMemberPath = 'DisplayName'
            $cmbOrganization.SelectedValuePath = 'Id'
            $cmbOrganization.SelectedIndex = 0
            $lblStatus.Text = "Connected to $($script:BaseUrl) - warning: unable to load organizations ($($_.Exception.Message))."
            Write-ConsoleLog -Level WARN -Message "Connected, but organization load failed: $($_.Exception.Message)"
        }

        Set-ConnectionUiState -Connected $true
        if ($lblStatus.Text -notmatch 'unable to load organizations') {
            $lblStatus.Text = "Connected to $($script:BaseUrl) - set filters and click Search."
        }
        Write-ConsoleLog -Level INFO -Message 'Connection successful.'
    }
    catch {
        $script:Organizations = @()
        $script:ClientId = ''
        $script:ClientSecret = ''
        $cmbOrganization.ItemsSource = @([pscustomobject]@{ DisplayName = 'All organizations'; Id = $null })
        $cmbOrganization.DisplayMemberPath = 'DisplayName'
        $cmbOrganization.SelectedValuePath = 'Id'
        $cmbOrganization.SelectedIndex = 0
        Set-ConnectionUiState -Connected $false
        $lblConnStatus.Text = 'Failed'
        $lblConnStatus.Foreground = [System.Windows.Media.Brushes]::Tomato
        $lblStatus.Text = "Error: $_"
        Write-ConsoleLog -Level ERROR -Message "Connection failed: $($_.Exception.Message)"
        [System.Windows.MessageBox]::Show($_.ToString(), 'Connection Failed', 'OK', 'Error') | Out-Null
    }
})

$btnSelectAllTypes.Add_Click({
    $lstTypes.UnselectAll()
    foreach ($type in $lstTypes.Items) {
        $lstTypes.SelectedItems.Add($type) | Out-Null
    }
})

$btnDeselectAllTypes.Add_Click({
    $lstTypes.UnselectAll()
})

$btnSearch.Add_Click({
    $selectedTypes = @($lstTypes.SelectedItems)

    if ($selectedTypes.Count -eq 0) {
        [System.Windows.MessageBox]::Show('Select at least one Activity Type.', 'No Types Selected', 'OK', 'Warning') | Out-Null
        return
    }

    try {
        $afterDate = Get-DateTimeFilterString -Date $dpAfter.SelectedDate -TimeText $txtAfterTime.Text -DefaultTime '00:00'
        $beforeDate = Get-DateTimeFilterString -Date $dpBefore.SelectedDate -TimeText $txtBeforeTime.Text -DefaultTime '23:59'
    }
    catch {
        [System.Windows.MessageBox]::Show($_.Exception.Message, 'Invalid Time', 'OK', 'Warning') | Out-Null
        return
    }
    $deviceFilter = $txtDeviceId.Text.Trim()
    $organizationId = [string]$cmbOrganization.SelectedValue
    if ([string]::IsNullOrWhiteSpace($script:ClientId) -or [string]::IsNullOrWhiteSpace($script:ClientSecret)) {
        [System.Windows.MessageBox]::Show('Credentials missing. Please reconnect first.', 'Not Connected', 'OK', 'Warning') | Out-Null
        return
    }

    $deviceId = $deviceFilter
    if (-not [string]::IsNullOrWhiteSpace($deviceFilter) -and $deviceFilter -notmatch '^\d+$') {
        $deviceId = Resolve-DeviceIdByHostname -Hostname $deviceFilter -ClientID $script:ClientId -ClientSecret $script:ClientSecret
        if ([string]::IsNullOrWhiteSpace($deviceId)) {
            [System.Windows.MessageBox]::Show("No device found for hostname '$deviceFilter'.", 'Device Not Found', 'OK', 'Warning') | Out-Null
            return
        }

        Write-ConsoleLog -Level INFO -Message "Resolved hostname '$deviceFilter' to deviceId $deviceId"
    }

    $btnSearch.IsEnabled = $false
    $btnSearch.Content = 'Searching...'
    $lblStatus.Text = 'Querying NinjaOne API...'
    $lblCount.Text = 'Loading...'

    Write-ConsoleLog -Level INFO -Message "Search started. After=$afterDate Before=$beforeDate DeviceFilter=$deviceFilter ResolvedDeviceId=$deviceId OrganizationId=$organizationId Types=$($selectedTypes -join ',')"
    if ([string]::IsNullOrWhiteSpace($organizationId)) {
        Write-ConsoleLog -Level DEBUG -Message 'Organization filter: All organizations (none applied).'
    }
    elseif (-not [string]::IsNullOrWhiteSpace($deviceId)) {
        Write-ConsoleLog -Level DEBUG -Message "Organization filter selected ($organizationId), but device-specific endpoint will be used when DeviceId is set."
    }
    else {
        Write-ConsoleLog -Level INFO -Message "Organization filter active: $organizationId"
    }

    try {
        $results = Get-Activities -Types $selectedTypes -After $afterDate -Before $beforeDate -DeviceId $deviceId -OrganizationId $organizationId -ClientID $script:ClientId -ClientSecret $script:ClientSecret
        $script:AllResults = @($results)
        Write-ConsoleLog -Level DEBUG -Message "Date-filtered result count: $($script:AllResults.Count)"

        $script:DataTable.Rows.Clear()
        foreach ($a in $script:AllResults) {
            $row = $script:DataTable.NewRow()
            $row['id'] = [string](Get-ObjectPropertyValue -InputObject $a -PropertyName 'id')
            $row['activityTime'] = ConvertFrom-EpochMs (Get-ObjectPropertyValue -InputObject $a -PropertyName 'activityTime')
            $row['deviceId'] = [string](Get-ObjectPropertyValue -InputObject $a -PropertyName 'deviceId')
            $row['hostname'] = Resolve-DeviceHostname -DeviceId $row['deviceId'] -ClientID $script:ClientId -ClientSecret $script:ClientSecret
            $row['activityType'] = [string](Get-ObjectPropertyValue -InputObject $a -PropertyName 'activityType')
            $row['statusCode'] = [string](Get-ObjectPropertyValue -InputObject $a -PropertyName 'statusCode')
            $row['severity'] = [string](Get-ObjectPropertyValue -InputObject $a -PropertyName 'severity')
            $row['details'] = Get-ActivityDetails -Activity $a
            [void]$script:DataTable.Rows.Add($row)
        }

        $count = $script:AllResults.Count
        $lblCount.Text = "Showing $count result(s)"
        $lblStatus.Text = "Search complete - $count activities returned."

        $btnExport.IsEnabled = ($count -gt 0)
        $btnCopy.IsEnabled = ($count -gt 0)

        Write-ConsoleLog -Level INFO -Message "Search completed. Returned $count activities."
    }
    catch {
        $lblCount.Text = 'Error'
        $lblStatus.Text = "Error: $_"
        Write-ConsoleLog -Level ERROR -Message "Search failed: $($_.Exception.Message)"
        [System.Windows.MessageBox]::Show($_.ToString(), 'Search Failed', 'OK', 'Error') | Out-Null
    }
    finally {
        $btnSearch.IsEnabled = $true
        $btnSearch.Content = 'Search'
    }
})

$btnExport.Add_Click({
    if (-not $script:AllResults -or $script:AllResults.Count -eq 0) { return }
    if ([string]::IsNullOrWhiteSpace($script:ClientId) -or [string]::IsNullOrWhiteSpace($script:ClientSecret)) {
        [System.Windows.MessageBox]::Show('Credentials missing. Please reconnect before exporting.', 'Reconnect Required', 'OK', 'Warning') | Out-Null
        return
    }

    $dlg = New-Object System.Windows.Forms.SaveFileDialog
    $dlg.Filter = 'CSV Files (*.csv)|*.csv'
    $dlg.FileName = "NinjaOne_Activities_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"

    if ($dlg.ShowDialog() -eq 'OK') {
        try {
            $script:AllResults | Select-Object @{N='Activity ID';E={ [string](Get-ObjectPropertyValue -InputObject $_ -PropertyName 'id') }},
                @{N='Activity Time';E={ ConvertFrom-EpochMs (Get-ObjectPropertyValue -InputObject $_ -PropertyName 'activityTime') }},
                @{N='Device ID';E={ [string](Get-ObjectPropertyValue -InputObject $_ -PropertyName 'deviceId') }},
                @{N='Hostname';E={ Resolve-DeviceHostname -DeviceId (Get-ObjectPropertyValue -InputObject $_ -PropertyName 'deviceId') -ClientID $script:ClientId -ClientSecret $script:ClientSecret }},
                @{N='Type';E={ [string](Get-ObjectPropertyValue -InputObject $_ -PropertyName 'activityType') }},
                @{N='Status';E={ [string](Get-ObjectPropertyValue -InputObject $_ -PropertyName 'statusCode') }},
                @{N='Severity';E={ [string](Get-ObjectPropertyValue -InputObject $_ -PropertyName 'severity') }},
                @{N='Details';E={ Get-ActivityDetails -Activity $_ }} |
                Export-Csv -Path $dlg.FileName -NoTypeInformation

            $lblStatus.Text = "Exported $($script:AllResults.Count) rows to: $($dlg.FileName)"
            Write-ConsoleLog -Level INFO -Message "Exported CSV to $($dlg.FileName)"
        }
        catch {
            Write-ConsoleLog -Level ERROR -Message "Export failed: $($_.Exception.Message)"
            [System.Windows.MessageBox]::Show($_.ToString(), 'Export Failed', 'OK', 'Error') | Out-Null
        }
    }
})

$btnCopy.Add_Click({
    if ($dataGridView.Items.Count -eq 0) { return }

    $selected = @($dataGridView.SelectedItems)
    if (-not $selected -or $selected.Count -eq 0) {
        $selected = @($dataGridView.ItemsSource)
    }

    $header = 'Activity ID`tActivity Time`tDevice ID`tHostname`tType`tStatus`tSeverity`tDetails'
    $lines = @($header)

    foreach ($row in $selected) {
        if ($row -and $row.Row) {
            $line = @(
                $row.Row.id,
                $row.Row.activityTime,
                $row.Row.deviceId,
                $row.Row.hostname,
                $row.Row.activityType,
                $row.Row.statusCode,
                $row.Row.severity,
                $row.Row.details
            ) -join "`t"
            $lines += $line
        }
    }

    [System.Windows.Clipboard]::SetText(($lines -join "`r`n"))
    $lblStatus.Text = "Copied $($selected.Count) row(s) to clipboard."
    Write-ConsoleLog -Level INFO -Message "Copied $($selected.Count) row(s) to clipboard"
})
#endregion

Write-ConsoleLog -Level INFO -Message 'Launching NinjaOne Activity Filter GUI.'
[void]$window.ShowDialog()
