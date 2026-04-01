#Requires -Version 5.1
<#
.SYNOPSIS
    NinjaOne Activity Filter GUI (WPF) using NinjaOne OAuth/API patterns.

.DESCRIPTION
    Standalone NinjaOne Activity Filter GUI for querying, filtering, and exporting activity data.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region --- Script state ---
$script:TokenInfo        = $null
$script:BaseUrl          = ''
$script:AllResults       = @()
$script:ProjectedRows    = @()
$script:DataTable        = New-Object System.Data.DataTable
$script:DeviceNameCache  = @{}
$script:HostnameDeviceCache = @{}
$script:statusFilters   = @()
$script:Organizations    = @()
$script:ClientId         = ''
$script:ClientSecret     = ''
$script:MaxPages         = 50
$script:DefaultPageSize  = 1000
$script:HeaderFilterTextBoxes = @{}
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

function Get-NinjaToken {
    param(
        [Parameter(Mandatory = $true)][string]$BaseUrl,
        [Parameter(Mandatory = $true)][string]$ClientID,
        [Parameter(Mandatory = $true)][string]$ClientSecret
    )

    $normalizedHost = Normalize-BaseUrl -Url $BaseUrl
    $tokenBody = @{
        grant_type    = 'client_credentials'
        client_id     = $ClientID
        client_secret = $ClientSecret
        scope         = 'monitoring management control'
    }

    Write-ConsoleLog -Level INFO -Message "Requesting OAuth token from $normalizedHost"
    $response = Invoke-RestMethod -Method Post -Uri "https://$normalizedHost/ws/oauth/token" -Body $tokenBody -ContentType 'application/x-www-form-urlencoded'

    $refreshToken = $null
    if ($response.PSObject.Properties.Name -contains 'refresh_token') {
        $refreshToken = [string]$response.refresh_token
    }

    return [pscustomobject]@{
        access_token  = [string]$response.access_token
        refresh_token = $refreshToken
        expires_in    = if ($response.PSObject.Properties.Name -contains 'expires_in') { [int]$response.expires_in } else { 0 }
        created_at    = Get-Date
    }
}

function Refresh-NinjaToken {
    param(
        [Parameter(Mandatory = $true)][string]$BaseUrl,
        [Parameter(Mandatory = $true)][string]$ClientID,
        [Parameter(Mandatory = $true)][string]$ClientSecret
    )

    if (-not $script:TokenInfo) {
        throw 'No token state available. Please reconnect.'
    }

    $hasRefreshProperty = $script:TokenInfo.PSObject.Properties.Name -contains 'refresh_token'
    $refreshToken = if ($hasRefreshProperty) { [string]$script:TokenInfo.refresh_token } else { '' }

    if ([string]::IsNullOrWhiteSpace($refreshToken)) {
        throw 'Current token has no refresh_token (common with client_credentials). Please reconnect.'
    }

    $normalizedHost = Normalize-BaseUrl -Url $BaseUrl
    $tokenBody = @{
        grant_type    = 'refresh_token'
        client_id     = $ClientID
        client_secret = $ClientSecret
        refresh_token = $refreshToken
    }

    Write-ConsoleLog -Level WARN -Message 'Received unauthorized response, attempting token refresh.'
    $response = Invoke-RestMethod -Method Post -Uri "https://$normalizedHost/ws/oauth/token" -Body $tokenBody -ContentType 'application/x-www-form-urlencoded'

    $newRefreshToken = if ($response.PSObject.Properties.Name -contains 'refresh_token') { [string]$response.refresh_token } else { $refreshToken }

    return [pscustomobject]@{
        access_token  = [string]$response.access_token
        refresh_token = $newRefreshToken
        expires_in    = if ($response.PSObject.Properties.Name -contains 'expires_in') { [int]$response.expires_in } else { 0 }
        created_at    = Get-Date
    }
}

function Get-AuthHeader {
    if (-not $script:TokenInfo -or [string]::IsNullOrWhiteSpace([string]$script:TokenInfo.access_token)) {
        throw 'Not connected. Please connect first.'
    }

    return @{ Authorization = "Bearer $($script:TokenInfo.access_token)" }
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
            try {
                $script:TokenInfo = Refresh-NinjaToken -BaseUrl $script:BaseUrl -ClientID $ClientID -ClientSecret $ClientSecret
                return Invoke-RestMethod -Method Get -Uri $uri -Headers (Get-AuthHeader)
            }
            catch {
                Write-ConsoleLog -Level ERROR -Message "Token refresh failed: $($_.Exception.Message)"
                throw 'Authentication failed and refresh was unavailable. Please click Connect again.'
            }
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

function Normalize-FilterText {
    param([AllowNull()][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    return $Text.Trim().ToLowerInvariant()
}

function Get-ActivityColumnValue {
    param(
        [Parameter(Mandatory = $true)]$Activity,
        [Parameter(Mandatory = $true)][string]$ColumnName
    )

    switch ($ColumnName) {
        'id' { return [string](Get-ObjectPropertyValue -InputObject $Activity -PropertyName 'id') }
        'activityTime' { return ConvertFrom-EpochMs (Get-ObjectPropertyValue -InputObject $Activity -PropertyName 'activityTime') }
        'deviceId' { return [string](Get-ObjectPropertyValue -InputObject $Activity -PropertyName 'deviceId') }
        'hostname' {
            $deviceId = [string](Get-ObjectPropertyValue -InputObject $Activity -PropertyName 'deviceId')
            return Resolve-DeviceHostname -DeviceId $deviceId -ClientID $script:ClientId -ClientSecret $script:ClientSecret
        }
        'activityType' { return [string](Get-ObjectPropertyValue -InputObject $Activity -PropertyName 'activityType') }
        'statusCode' { return [string](Get-ObjectPropertyValue -InputObject $Activity -PropertyName 'statusCode') }
        'severity' { return [string](Get-ObjectPropertyValue -InputObject $Activity -PropertyName 'severity') }
        'details' { return Get-ActivityDetails -Activity $Activity }
        default { return '' }
    }
}

function Convert-ActivitiesToProjectedRows {
    param([object[]]$Activities)

    $projectedRows = @()
    foreach ($activity in @(if ($null -eq $Activities) { @() } else { $Activities })) {
        $deviceId = [string](Get-ObjectPropertyValue -InputObject $activity -PropertyName 'deviceId')
        $projectedRows += [pscustomobject]@{
            id           = [string](Get-ObjectPropertyValue -InputObject $activity -PropertyName 'id')
            activityTime = ConvertFrom-EpochMs (Get-ObjectPropertyValue -InputObject $activity -PropertyName 'activityTime')
            deviceId     = $deviceId
            hostname     = Resolve-DeviceHostname -DeviceId $deviceId -ClientID $script:ClientId -ClientSecret $script:ClientSecret
            activityType = [string](Get-ObjectPropertyValue -InputObject $activity -PropertyName 'activityType')
            statusCode   = [string](Get-ObjectPropertyValue -InputObject $activity -PropertyName 'statusCode')
            severity     = [string](Get-ObjectPropertyValue -InputObject $activity -PropertyName 'severity')
            details      = Get-ActivityDetails -Activity $activity
        }
    }

    return @($projectedRows)
}

function Get-ActiveColumnFilterMap {
    $filterMap = @{}
    foreach ($column in @('id','activityTime','deviceId','hostname','activityType','statusCode','severity','details')) {
        $rawValues = @()
        if ($script:HeaderFilterTextBoxes.ContainsKey($column)) {
            $rawValues += $script:HeaderFilterTextBoxes[$column].Text
        }

        $activeValues = @($rawValues | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if ($activeValues.Count -gt 0) {
            $filterMap[$column] = $activeValues
        }
    }

    return $filterMap
}

function Apply-ColumnFilters {
    param([hashtable]$FilterMap)

    $allProjectedRows = @(if ($null -eq $script:ProjectedRows) { @() } else { $script:ProjectedRows })
    $normalizedFilters = @{}
    if ($FilterMap) {
        foreach ($entry in $FilterMap.GetEnumerator()) {
            $needles = @()
            foreach ($value in @($entry.Value)) {
                $normalized = Normalize-FilterText -Text ([string]$value)
                if (-not [string]::IsNullOrWhiteSpace($normalized)) {
                    $needles += $normalized
                }
            }

            if ($needles.Count -gt 0) {
                $normalizedFilters[[string]$entry.Key] = $needles
            }
        }
    }

    $hasActiveFilters = ($normalizedFilters.Count -gt 0)
    $visibleRows = foreach ($projectedRow in $allProjectedRows) {
        $isMatch = $true
        foreach ($entry in $normalizedFilters.GetEnumerator()) {
            $columnValue = [string](Get-ObjectPropertyValue -InputObject $projectedRow -PropertyName ([string]$entry.Key))
            $normalizedRowValue = Normalize-FilterText -Text ([string]$columnValue)
            foreach ($needle in @($entry.Value)) {
                if (-not $normalizedRowValue.Contains($needle)) {
                    $isMatch = $false
                    break
                }
            }

            if (-not $isMatch) { break }
        }

        if ($isMatch) { $projectedRow }
    }

    $script:DataTable.Rows.Clear()
    foreach ($projectedRow in @($visibleRows)) {
        $row = $script:DataTable.NewRow()
        $row['id'] = [string]$projectedRow.id
        $row['activityTime'] = [string]$projectedRow.activityTime
        $row['deviceId'] = [string]$projectedRow.deviceId
        $row['hostname'] = [string]$projectedRow.hostname
        $row['activityType'] = [string]$projectedRow.activityType
        $row['statusCode'] = [string]$projectedRow.statusCode
        $row['severity'] = [string]$projectedRow.severity
        $row['details'] = [string]$projectedRow.details
        [void]$script:DataTable.Rows.Add($row)
    }

    $visibleCount = $script:DataTable.Rows.Count
    $totalCount = $allProjectedRows.Count
    if (-not $hasActiveFilters) {
        $lblCount.Text = "Showing $visibleCount result(s)"
    }
    else {
        $lblCount.Text = "Showing $visibleCount of $totalCount result(s) (Column filters active)."
    }

    $btnExport.IsEnabled = ($visibleCount -gt 0)
    $btnCopy.IsEnabled = ($visibleCount -gt 0)
}

function Get-VisualChildTextBoxes {
    param([Parameter(Mandatory = $true)][System.Windows.DependencyObject]$Root)

    $children = @()
    $count = [System.Windows.Media.VisualTreeHelper]::GetChildrenCount($Root)
    for ($i = 0; $i -lt $count; $i++) {
        $child = [System.Windows.Media.VisualTreeHelper]::GetChild($Root, $i)
        if ($child -is [System.Windows.Controls.TextBox]) {
            $children += $child
        }

        $children += @(Get-VisualChildTextBoxes -Root $child)
    }

    return $children
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
        <Style x:Key="HeaderFilterTextBoxStyle" TargetType="TextBox" BasedOn="{StaticResource {x:Type TextBox}}">
            <Setter Property="Height" Value="24"/>
            <Setter Property="Padding" Value="6,2"/>
            <Setter Property="Margin" Value="0"/>
            <Setter Property="VerticalAlignment" Value="Top"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Background" Value="{StaticResource InputBg}"/>
            <Setter Property="Foreground" Value="{StaticResource TextPrimary}"/>
            <Setter Property="BorderBrush" Value="#475569"/>
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
                <TextBox Grid.Column="1" x:Name="txtDomain" Height="26" Text="eu.ninjarmm.com"/>
                <TextBlock Grid.Column="2" Text="Client ID:" VerticalAlignment="Center" Margin="12,0,8,0"/>
                <PasswordBox Grid.Column="3" x:Name="txtClientId" Height="26"/>
                <TextBlock Grid.Column="4" Text="Secret:" VerticalAlignment="Center" Margin="12,0,8,0"/>
                <PasswordBox Grid.Column="5" x:Name="txtSecret" Height="26"/>
                <Button Grid.Column="6" x:Name="btnConnect" Content="Connect" Height="26" Width="100" Margin="12,0,0,0"/>
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
                        <TextBlock Text="Result info" FontWeight="SemiBold" Margin="0,6,0,4"/>
                        <Border Background="#0F172A" BorderBrush="#334155" BorderThickness="1" CornerRadius="6" Padding="8">
                            <StackPanel>
                                <TextBlock x:Name="lblCount" Text="No results" Foreground="{StaticResource TextMuted}" Margin="0,0,0,6"/>
                                <TextBlock x:Name="lblStatus" Text="Ready. Connect to NinjaOne to begin." Foreground="{StaticResource TextPrimary}" TextWrapping="Wrap"/>
                            </StackPanel>
                        </Border>
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
                    <Setter Property="VerticalContentAlignment" Value="Top"/>
                    <Setter Property="HorizontalContentAlignment" Value="Stretch"/>
                    <Setter Property="Padding" Value="8,6,8,6"/>
                </Style>
            </DataGrid.ColumnHeaderStyle>
            <DataGrid.Columns>
                <DataGridTextColumn Binding="{Binding id}" Width="100" MinWidth="80">
                    <DataGridTextColumn.HeaderTemplate>
                        <DataTemplate>
                            <Grid HorizontalAlignment="Stretch" VerticalAlignment="Stretch">
                                <Grid.RowDefinitions>
                                    <RowDefinition Height="Auto"/>
                                    <RowDefinition Height="24"/>
                                </Grid.RowDefinitions>
                                <TextBlock Grid.Row="0" Text="Activity ID" Margin="0,0,0,4" FontWeight="SemiBold" VerticalAlignment="Center"/>
                                <TextBox Grid.Row="1" x:Name="txtFilterId" Tag="id" Text="" ToolTip="Filter by Activity ID" HorizontalAlignment="Stretch" Style="{StaticResource HeaderFilterTextBoxStyle}"/>
                            </Grid>
                        </DataTemplate>
                    </DataGridTextColumn.HeaderTemplate>
                </DataGridTextColumn>
                <DataGridTextColumn Binding="{Binding activityTime}" Width="170">
                    <DataGridTextColumn.HeaderTemplate>
                        <DataTemplate>
                            <Grid HorizontalAlignment="Stretch" VerticalAlignment="Stretch">
                                <Grid.RowDefinitions>
                                    <RowDefinition Height="Auto"/>
                                    <RowDefinition Height="24"/>
                                </Grid.RowDefinitions>
                                <TextBlock Grid.Row="0" Text="Activity Time" Margin="0,0,0,4" FontWeight="SemiBold" VerticalAlignment="Center"/>
                                <TextBox Grid.Row="1" x:Name="txtFilterActivityTime" Tag="activityTime" Text="" ToolTip="Filter by Activity Time" HorizontalAlignment="Stretch" Style="{StaticResource HeaderFilterTextBoxStyle}"/>
                            </Grid>
                        </DataTemplate>
                    </DataGridTextColumn.HeaderTemplate>
                </DataGridTextColumn>
                <DataGridTextColumn Binding="{Binding deviceId}" Width="100" MinWidth="80">
                    <DataGridTextColumn.HeaderTemplate>
                        <DataTemplate>
                            <Grid HorizontalAlignment="Stretch" VerticalAlignment="Stretch">
                                <Grid.RowDefinitions>
                                    <RowDefinition Height="Auto"/>
                                    <RowDefinition Height="24"/>
                                </Grid.RowDefinitions>
                                <TextBlock Grid.Row="0" Text="Device ID" Margin="0,0,0,4" FontWeight="SemiBold" VerticalAlignment="Center"/>
                                <TextBox Grid.Row="1" x:Name="txtFilterDeviceId" Tag="deviceId" Text="" ToolTip="Filter by Device ID" HorizontalAlignment="Stretch" Style="{StaticResource HeaderFilterTextBoxStyle}"/>
                            </Grid>
                        </DataTemplate>
                    </DataGridTextColumn.HeaderTemplate>
                </DataGridTextColumn>
                <DataGridTextColumn Binding="{Binding hostname}" Width="180">
                    <DataGridTextColumn.HeaderTemplate>
                        <DataTemplate>
                            <Grid HorizontalAlignment="Stretch" VerticalAlignment="Stretch">
                                <Grid.RowDefinitions>
                                    <RowDefinition Height="Auto"/>
                                    <RowDefinition Height="24"/>
                                </Grid.RowDefinitions>
                                <TextBlock Grid.Row="0" Text="Hostname" Margin="0,0,0,4" FontWeight="SemiBold" VerticalAlignment="Center"/>
                                <TextBox Grid.Row="1" x:Name="txtFilterHostname" Tag="hostname" Text="" ToolTip="Filter by Hostname" HorizontalAlignment="Stretch" Style="{StaticResource HeaderFilterTextBoxStyle}"/>
                            </Grid>
                        </DataTemplate>
                    </DataGridTextColumn.HeaderTemplate>
                </DataGridTextColumn>
                <DataGridTextColumn Binding="{Binding activityType}" Width="180">
                    <DataGridTextColumn.HeaderTemplate>
                        <DataTemplate>
                            <Grid HorizontalAlignment="Stretch" VerticalAlignment="Stretch">
                                <Grid.RowDefinitions>
                                    <RowDefinition Height="Auto"/>
                                    <RowDefinition Height="24"/>
                                </Grid.RowDefinitions>
                                <TextBlock Grid.Row="0" Text="Type" Margin="0,0,0,4" FontWeight="SemiBold" VerticalAlignment="Center"/>
                                <TextBox Grid.Row="1" x:Name="txtFilterActivityType" Tag="activityType" Text="" ToolTip="Filter by Type" HorizontalAlignment="Stretch" Style="{StaticResource HeaderFilterTextBoxStyle}"/>
                            </Grid>
                        </DataTemplate>
                    </DataGridTextColumn.HeaderTemplate>
                </DataGridTextColumn>
                <DataGridTextColumn Binding="{Binding statusCode}" Width="160">
                    <DataGridTextColumn.HeaderTemplate>
                        <DataTemplate>
                            <Grid HorizontalAlignment="Stretch" VerticalAlignment="Stretch">
                                <Grid.RowDefinitions>
                                    <RowDefinition Height="Auto"/>
                                    <RowDefinition Height="24"/>
                                </Grid.RowDefinitions>
                                <TextBlock Grid.Row="0" Text="Status" Margin="0,0,0,4" FontWeight="SemiBold" VerticalAlignment="Center"/>
                                <TextBox Grid.Row="1" x:Name="txtFilterStatusCode" Tag="statusCode" Text="" ToolTip="Filter by Status" HorizontalAlignment="Stretch" Style="{StaticResource HeaderFilterTextBoxStyle}"/>
                            </Grid>
                        </DataTemplate>
                    </DataGridTextColumn.HeaderTemplate>
                </DataGridTextColumn>
                <DataGridTextColumn Binding="{Binding severity}" Width="120">
                    <DataGridTextColumn.HeaderTemplate>
                        <DataTemplate>
                            <Grid HorizontalAlignment="Stretch" VerticalAlignment="Stretch">
                                <Grid.RowDefinitions>
                                    <RowDefinition Height="Auto"/>
                                    <RowDefinition Height="24"/>
                                </Grid.RowDefinitions>
                                <TextBlock Grid.Row="0" Text="Severity" Margin="0,0,0,4" FontWeight="SemiBold" VerticalAlignment="Center"/>
                                <TextBox Grid.Row="1" x:Name="txtFilterSeverity" Tag="severity" Text="" ToolTip="Filter by Severity" HorizontalAlignment="Stretch" Style="{StaticResource HeaderFilterTextBoxStyle}"/>
                            </Grid>
                        </DataTemplate>
                    </DataGridTextColumn.HeaderTemplate>
                </DataGridTextColumn>
                <DataGridTemplateColumn Header="Details" Width="*" MinWidth="520">
                    <DataGridTemplateColumn.HeaderTemplate>
                        <DataTemplate>
                            <Grid HorizontalAlignment="Stretch" VerticalAlignment="Stretch">
                                <Grid.RowDefinitions>
                                    <RowDefinition Height="Auto"/>
                                    <RowDefinition Height="24"/>
                                </Grid.RowDefinitions>
                                <TextBlock Grid.Row="0" Text="Details" Margin="0,0,0,4" FontWeight="SemiBold" VerticalAlignment="Center"/>
                                <TextBox Grid.Row="1" x:Name="txtFilterDetails" Tag="details" Text="" ToolTip="Filter by Details" HorizontalAlignment="Stretch" Style="{StaticResource HeaderFilterTextBoxStyle}"/>
                            </Grid>
                        </DataTemplate>
                    </DataGridTemplateColumn.HeaderTemplate>
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

$txtDomain     = $window.FindName('txtDomain')
$txtClientId   = $window.FindName('txtClientId')
$txtSecret     = $window.FindName('txtSecret')
$btnConnect    = $window.FindName('btnConnect')
$lblConnStatus = $window.FindName('lblConnStatus')
$dpAfter       = $window.FindName('dpAfter')
$dpBefore      = $window.FindName('dpBefore')
$txtAfterTime  = $window.FindName('txtAfterTime')
$txtBeforeTime = $window.FindName('txtBeforeTime')
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

$supportedDomains = @('app.ninjarmm.com','eu.ninjarmm.com','ca.ninjarmm.com','oc.ninjarmm.com','us2.ninjarmm.com')
$txtDomain.ToolTip = "Supported domains: $($supportedDomains -join ', ')"

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

#region --- Event handlers ---
$btnConnect.Add_Click({
    $domain = $txtDomain.Text.Trim()
    $clientId = $txtClientId.Password.Trim()
    $secret = $txtSecret.Password

    if ([string]::IsNullOrWhiteSpace($domain) -or [string]::IsNullOrWhiteSpace($clientId) -or [string]::IsNullOrWhiteSpace($secret)) {
        [System.Windows.MessageBox]::Show('Please fill in Domain, Client ID, and Client Secret.', 'Missing Fields', 'OK', 'Warning') | Out-Null
        return
    }

    Write-ConsoleLog -Level INFO -Message "Connecting to NinjaOne tenant $domain"

    try {
        $script:BaseUrl = Normalize-BaseUrl -Url $domain
        $script:TokenInfo = Get-NinjaToken -BaseUrl $script:BaseUrl -ClientID $clientId -ClientSecret $secret
        $script:DeviceNameCache = @{}
        $script:HostnameDeviceCache = @{}
        $script:Organizations = @()
        $script:ClientId = $clientId
        $script:ClientSecret = $secret

        try {
            $organizationOptions = Get-Organizations -ClientID $clientId -ClientSecret $secret
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
            $lblStatus.Text = "Connected to $($script:BaseUrl) — warning: unable to load organizations ($($_.Exception.Message))."
            Write-ConsoleLog -Level WARN -Message "Connected, but organization load failed: $($_.Exception.Message)"
        }

        $lblConnStatus.Text = 'Connected'
        $lblConnStatus.Foreground = [System.Windows.Media.Brushes]::LimeGreen
        $btnSearch.IsEnabled = $true
        if ($lblStatus.Text -notmatch 'unable to load organizations') {
            $lblStatus.Text = "Connected to $($script:BaseUrl) — set filters and click Search."
        }
        Write-ConsoleLog -Level INFO -Message 'Connection successful.'
    }
    catch {
        $script:ClientId = ''
        $script:ClientSecret = ''
        $lblConnStatus.Text = 'Failed'
        $lblConnStatus.Foreground = [System.Windows.Media.Brushes]::Tomato
        $btnSearch.IsEnabled = $false
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
    $organizationId = [string]$cmbOrganization.SelectedValue
    if ([string]::IsNullOrWhiteSpace($script:ClientId) -or [string]::IsNullOrWhiteSpace($script:ClientSecret)) {
        [System.Windows.MessageBox]::Show('Credentials missing. Please reconnect first.', 'Not Connected', 'OK', 'Warning') | Out-Null
        return
    }

    $btnSearch.IsEnabled = $false
    $btnSearch.Content = 'Searching...'
    $lblStatus.Text = 'Querying NinjaOne API...'
    $lblCount.Text = 'Loading...'

    Write-ConsoleLog -Level INFO -Message "Search started. After=$afterDate Before=$beforeDate OrganizationId=$organizationId Types=$($selectedTypes -join ',')"
    if ([string]::IsNullOrWhiteSpace($organizationId)) {
        Write-ConsoleLog -Level DEBUG -Message 'Organization filter: All organizations (none applied).'
    }
    else {
        Write-ConsoleLog -Level INFO -Message "Organization filter active: $organizationId"
    }

    try {
        $results = Get-Activities -Types $selectedTypes -After $afterDate -Before $beforeDate -DeviceId '' -OrganizationId $organizationId -ClientID $script:ClientId -ClientSecret $script:ClientSecret
        $script:AllResults = @($results)
        $script:ProjectedRows = Convert-ActivitiesToProjectedRows -Activities $script:AllResults
        Write-ConsoleLog -Level DEBUG -Message "Date-filtered result count: $(@($script:AllResults).Count)"
        Write-ConsoleLog -Level DEBUG -Message "Projected row cache count: $(@($script:ProjectedRows).Count)"
        Apply-ColumnFilters -FilterMap (Get-ActiveColumnFilterMap)

        $count = $script:DataTable.Rows.Count
        $lblStatus.Text = "Search complete — $count visible activities returned."

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
    $visibleRows = @($dataGridView.ItemsSource)
    if ($visibleRows.Count -eq 0) { return }
    if ([string]::IsNullOrWhiteSpace($script:ClientId) -or [string]::IsNullOrWhiteSpace($script:ClientSecret)) {
        [System.Windows.MessageBox]::Show('Credentials missing. Please reconnect before exporting.', 'Reconnect Required', 'OK', 'Warning') | Out-Null
        return
    }

    $dlg = New-Object System.Windows.Forms.SaveFileDialog
    $dlg.Filter = 'CSV Files (*.csv)|*.csv'
    $dlg.FileName = "NinjaOne_Activities_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"

    if ($dlg.ShowDialog() -eq 'OK') {
        try {
            $visibleRows | ForEach-Object {
                [pscustomobject]@{
                    'Activity ID'   = [string]$_.Row.id
                    'Activity Time' = [string]$_.Row.activityTime
                    'Device ID'     = [string]$_.Row.deviceId
                    'Hostname'      = [string]$_.Row.hostname
                    'Type'          = [string]$_.Row.activityType
                    'Status'        = [string]$_.Row.statusCode
                    'Severity'      = [string]$_.Row.severity
                    'Details'       = [string]$_.Row.details
                }
            } |
                Export-Csv -Path $dlg.FileName -NoTypeInformation

            $lblStatus.Text = "Exported $($visibleRows.Count) visible row(s) to: $($dlg.FileName)"
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

$window.Add_ContentRendered({
    if ($script:HeaderFilterTextBoxes.Count -gt 0) { return }

    $filterableColumns = @('id','activityTime','deviceId','hostname','activityType','statusCode','severity','details')
    $allTextBoxes = Get-VisualChildTextBoxes -Root $dataGridView
    foreach ($textBox in $allTextBoxes) {
        $tagName = [string]$textBox.Tag
        if ([string]::IsNullOrWhiteSpace($tagName) -or $filterableColumns -notcontains $tagName) { continue }
        if ($script:HeaderFilterTextBoxes.ContainsKey($tagName)) { continue }

        $script:HeaderFilterTextBoxes[$tagName] = $textBox
        $textBox.Add_TextChanged({
            Apply-ColumnFilters -FilterMap (Get-ActiveColumnFilterMap)
        })
    }
})
#endregion

Write-ConsoleLog -Level INFO -Message 'Launching NinjaOne Activity Filter GUI.'
[void]$window.ShowDialog()
