Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:NinjaTokenInfo = $null
$script:NinjaCurrentState = $null

function Get-NinjaOAuthErrorDetail {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$ErrorRecord
    )

    $details = @()

    $errorDetailsMessage = [string]$ErrorRecord.ErrorDetails.Message
    if (-not [string]::IsNullOrWhiteSpace($errorDetailsMessage)) {
        try {
            $parsed = $errorDetailsMessage | ConvertFrom-Json -ErrorAction Stop
            if ($parsed.resultCode) { $details += "resultCode=$($parsed.resultCode)" }
            if ($parsed.resultMessage) { $details += "resultMessage=$($parsed.resultMessage)" }
            if ($parsed.incidentId) { $details += "incidentId=$($parsed.incidentId)" }
        }
        catch {
            $details += $errorDetailsMessage
        }
    }

    if ($details.Count -eq 0) {
        $details += [string]$ErrorRecord.Exception.Message
    }

    return ($details -join '; ')
}


function Get-MaskedClientId {
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$ClientId)

    if ([string]::IsNullOrWhiteSpace($ClientId)) { return '<empty>' }

    $trimmed = $ClientId.Trim()
    if ($trimmed.Length -le 8) { return ('*' * $trimmed.Length) }

    return ('{0}...{1}' -f $trimmed.Substring(0, 4), $trimmed.Substring($trimmed.Length - 4))
}

function Get-ClientIdSource {
    [CmdletBinding()]
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

function ConvertFrom-QueryString {
    [CmdletBinding()]
    param(
        [AllowNull()][string]$QueryString
    )

    $result = @{}
    if ([string]::IsNullOrWhiteSpace($QueryString)) { return $result }

    $raw = $QueryString.TrimStart('?')
    if ([string]::IsNullOrWhiteSpace($raw)) { return $result }

    foreach ($pair in $raw -split '&') {
        if ([string]::IsNullOrWhiteSpace($pair)) { continue }
        $kv = $pair -split '=', 2
        $key = [System.Uri]::UnescapeDataString($kv[0])
        $value = if ($kv.Count -gt 1) { [System.Uri]::UnescapeDataString($kv[1]) } else { '' }
        if (-not [string]::IsNullOrWhiteSpace($key)) {
            $result[$key] = $value
        }
    }

    return $result
}

function ConvertTo-FormUrlEncoded {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Data
    )

    ($Data.GetEnumerator() | ForEach-Object {
        '{0}={1}' -f [uri]::EscapeDataString([string]$_.Key), [uri]::EscapeDataString([string]$_.Value)
    }) -join '&'
}

function New-NinjaOAuthState {
    [CmdletBinding()]
    param(
        [int]$ByteLength = 32
    )

    if ($ByteLength -lt 16) {
        throw 'State byte length must be at least 16.'
    }

    $bytes = New-Object byte[] $ByteLength
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $state = [Convert]::ToBase64String($bytes).TrimEnd('=') -replace '\+','-' -replace '/','_'

    $script:NinjaCurrentState = [pscustomobject]@{
        Value     = $state
        CreatedAt = Get-Date
    }

    return $script:NinjaCurrentState.Value
}

function Get-NinjaAuthorizationUrl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory)][string]$RedirectUri,
        [Parameter(Mandatory)][string[]]$Scopes,
        [Parameter(Mandatory)][string]$State,
        [Parameter(Mandatory)][string]$AuthorizationEndpoint
    )

    if (-not [Uri]::IsWellFormedUriString($RedirectUri, [UriKind]::Absolute)) {
        throw 'Redirect URI must be an absolute URI.'
    }

    $scopeString = ($Scopes | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join ' '
    if ([string]::IsNullOrWhiteSpace($scopeString)) {
        throw 'At least one scope is required.'
    }

    $query = @{
        response_type = 'code'
        client_id     = $ClientId
        redirect_uri  = $RedirectUri
        scope         = $scopeString
        state         = $State
    }

    return '{0}?{1}' -f $AuthorizationEndpoint.TrimEnd('/'), (ConvertTo-FormUrlEncoded -Data $query)
}

function Start-NinjaOAuthLogin {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$AuthorizationUrl
    )

    try {
        Start-Process $AuthorizationUrl | Out-Null
        [pscustomobject]@{
            Success = $true
            Message = 'Browser opened for NinjaOne login.'
        }
    }
    catch {
        throw "Failed to launch the browser. Open this URL manually: $AuthorizationUrl"
    }
}

function Wait-NinjaOAuthCallback {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RedirectUri,
        [int]$TimeoutSeconds = 180
    )

    $redirect = [Uri]$RedirectUri
    if ($redirect.Scheme -notin @('http', 'https')) {
        throw 'Redirect URI must use http or https scheme for local listener callback.'
    }

    $prefix = '{0}://{1}:{2}{3}' -f $redirect.Scheme, $redirect.Host, $redirect.Port, '/'

    $listener = [System.Net.HttpListener]::new()
    $listener.Prefixes.Add($prefix)

    try {
        $listener.Start()
    }
    catch {
        throw "Unable to start local callback listener on $prefix. Ensure the port is available and try again. Error: $($_.Exception.Message)"
    }

    try {
        $task = $listener.GetContextAsync()
        $finished = $task.Wait([TimeSpan]::FromSeconds($TimeoutSeconds))

        if (-not $finished) {
            throw "Timed out waiting for OAuth callback after $TimeoutSeconds seconds."
        }

        $context = $task.Result
        $request = $context.Request
        $response = $context.Response

        if ($request.Url.AbsolutePath -ne $redirect.AbsolutePath) {
            $response.StatusCode = 400
            $bytes = [Text.Encoding]::UTF8.GetBytes('Invalid callback path.')
            $response.OutputStream.Write($bytes, 0, $bytes.Length)
            $response.Close()
            throw 'Received callback on unexpected path.'
        }

        $query = ConvertFrom-QueryString -QueryString $request.Url.Query

        $code  = [string]$query['code']
        $state = [string]$query['state']
        $error = [string]$query['error']
        $errorDescription = [string]$query['error_description']

        if (-not [string]::IsNullOrWhiteSpace($error)) {
            $response.StatusCode = 400
            $msg = "Authentication failed: $error"
            if (-not [string]::IsNullOrWhiteSpace($errorDescription)) {
                $msg = "$msg ($errorDescription)"
            }
            $bytes = [Text.Encoding]::UTF8.GetBytes($msg)
            $response.OutputStream.Write($bytes, 0, $bytes.Length)
            $response.Close()
            throw $msg
        }

        if ([string]::IsNullOrWhiteSpace($code) -or [string]::IsNullOrWhiteSpace($state)) {
            $response.StatusCode = 400
            $bytes = [Text.Encoding]::UTF8.GetBytes('Missing code or state in callback.')
            $response.OutputStream.Write($bytes, 0, $bytes.Length)
            $response.Close()
            throw 'Missing required callback parameters (code/state).'
        }

        $response.StatusCode = 200
        $ok = 'Login completed. You can close this browser window.'
        $okBytes = [Text.Encoding]::UTF8.GetBytes($ok)
        $response.OutputStream.Write($okBytes, 0, $okBytes.Length)
        $response.Close()

        return [pscustomobject]@{
            Code  = $code
            State = $state
            RawUrl = $request.Url.AbsoluteUri
        }
    }
    finally {
        if ($listener.IsListening) {
            $listener.Stop()
        }
        $listener.Close()
    }
}

function Test-NinjaOAuthState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ExpectedState,
        [Parameter(Mandatory)][string]$ReturnedState
    )

    if ([string]::IsNullOrWhiteSpace($ExpectedState) -or [string]::IsNullOrWhiteSpace($ReturnedState)) {
        return $false
    }

    $a = [Text.Encoding]::UTF8.GetBytes($ExpectedState)
    $b = [Text.Encoding]::UTF8.GetBytes($ReturnedState)

    if ($a.Length -ne $b.Length) {
        return $false
    }

    return [System.Security.Cryptography.CryptographicOperations]::FixedTimeEquals($a, $b)
}


function ConvertTo-NinjaTokenInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$TokenResponse,
        [string]$FallbackRefreshToken
    )

    $expiresInValue = 0
    $rawExpiresIn = [string]$TokenResponse.expires_in
    if (-not [int]::TryParse($rawExpiresIn.Trim(), [ref]$expiresInValue)) {
        throw "Token response is invalid: expires_in value '$rawExpiresIn' is not a valid integer."
    }

    $resolvedRefreshToken = [string]$TokenResponse.refresh_token
    if ([string]::IsNullOrWhiteSpace($resolvedRefreshToken)) {
        $resolvedRefreshToken = [string]$FallbackRefreshToken
    }

    return [pscustomobject]@{
        access_token  = [string]$TokenResponse.access_token
        refresh_token = $resolvedRefreshToken
        token_type    = [string]$TokenResponse.token_type
        scope         = [string]$TokenResponse.scope
        expires_in    = $expiresInValue
        created_at    = Get-Date
    }
}

function Request-NinjaOAuthToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TokenEndpoint,
        [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory)][string]$ClientSecret,
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][string]$RedirectUri,
        [int]$TimeoutSeconds = 60
    )

    if ([string]::IsNullOrWhiteSpace($ClientSecret)) {
        throw 'Client secret is required for confidential web app token exchange.'
    }

    $body = @{
        grant_type    = 'authorization_code'
        client_id     = $ClientId
        client_secret = $ClientSecret
        code          = $Code
        redirect_uri  = $RedirectUri
    }

    try {
        $response = Invoke-RestMethod -Method Post -Uri $TokenEndpoint -ContentType 'application/x-www-form-urlencoded' -Body (ConvertTo-FormUrlEncoded -Data $body) -TimeoutSec $TimeoutSeconds
    }
    catch {
        $errorDetail = Get-NinjaOAuthErrorDetail -ErrorRecord $_

        if ($errorDetail -match 'Client app not exist') {
            throw "Failed to exchange authorization code for tokens. NinjaOne returned 'Client app not exist'. Verify: (1) app is created in this exact tenant domain, (2) app platform/type is Web Authentication (confidential client with secret), (3) Authorization Code flow is enabled for the app (some NinjaOne UI variants may hide this after save), and (4) app changes are saved in NinjaOne (Update). Error: $errorDetail"
        }

        throw "Failed to exchange authorization code for tokens. Check tenant domain, redirect URI, and client app configuration (Client ID/secret and enabled grant type). Error: $errorDetail"
    }

    $token = ConvertTo-NinjaTokenInfo -TokenResponse $response

    $script:NinjaTokenInfo = $token
    return $token
}

function Refresh-NinjaOAuthToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TokenEndpoint,
        [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory)][string]$ClientSecret,
        [Parameter(Mandatory)][string]$RefreshToken,
        [int]$TimeoutSeconds = 60
    )

    if ([string]::IsNullOrWhiteSpace($RefreshToken)) {
        throw 'Refresh token is missing. Include offline_access scope and re-authenticate.'
    }

    $body = @{
        grant_type    = 'refresh_token'
        client_id     = $ClientId
        client_secret = $ClientSecret
        refresh_token = $RefreshToken
    }

    try {
        $response = Invoke-RestMethod -Method Post -Uri $TokenEndpoint -ContentType 'application/x-www-form-urlencoded' -Body (ConvertTo-FormUrlEncoded -Data $body) -TimeoutSec $TimeoutSeconds
    }
    catch {
        $errorDetail = Get-NinjaOAuthErrorDetail -ErrorRecord $_
        throw "Failed to refresh access token. Re-login may be required and verify client app settings. Error: $errorDetail"
    }

    $token = ConvertTo-NinjaTokenInfo -TokenResponse $response -FallbackRefreshToken $RefreshToken

    $script:NinjaTokenInfo = $token
    return $token
}

function Get-ValidNinjaAccessToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TokenEndpoint,
        [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory)][string]$ClientSecret,
        [int]$RefreshBeforeSeconds = 120,
        [int]$TimeoutSeconds = 60
    )

    if (-not $script:NinjaTokenInfo) {
        throw 'No token is loaded. Authenticate first or call Load-NinjaTokenCache.'
    }

    $expiresIn = 0
    $rawExpiresIn = [string]$script:NinjaTokenInfo.expires_in
    if (-not [int]::TryParse($rawExpiresIn.Trim(), [ref]$expiresIn)) {
        throw "Cached token is invalid: expires_in value '$rawExpiresIn' is not a valid integer. Delete the token cache and authenticate again."
    }

    $createdAt = [datetime]::MinValue
    $rawCreatedAt = [string]$script:NinjaTokenInfo.created_at
    if (-not [datetime]::TryParse($rawCreatedAt.Trim(), [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind, [ref]$createdAt)) {
        throw "Cached token is invalid: created_at value '$rawCreatedAt' is not a valid datetime. Delete the token cache and authenticate again."
    }
    $expiresAt = $createdAt.AddSeconds($expiresIn)
    $needsRefresh = (Get-Date).AddSeconds($RefreshBeforeSeconds) -ge $expiresAt

    if ($needsRefresh) {
        $null = Refresh-NinjaOAuthToken -TokenEndpoint $TokenEndpoint -ClientId $ClientId -ClientSecret $ClientSecret -RefreshToken $script:NinjaTokenInfo.refresh_token -TimeoutSeconds $TimeoutSeconds
    }

    return [string]$script:NinjaTokenInfo.access_token
}

function Invoke-NinjaApiRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('GET','POST','PUT','PATCH','DELETE')] [string]$Method,
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][string]$AccessToken,
        [object]$Body,
        [int]$TimeoutSeconds = 60
    )

    if ([string]::IsNullOrWhiteSpace($AccessToken)) {
        throw 'Access token is empty. Obtain a valid token first.'
    }

    $headers = @{ Authorization = "Bearer $AccessToken" }

    try {
        if ($PSBoundParameters.ContainsKey('Body')) {
            return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -Body ($Body | ConvertTo-Json -Depth 10) -ContentType 'application/json' -TimeoutSec $TimeoutSeconds
        }

        return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -TimeoutSec $TimeoutSeconds
    }
    catch {
        throw "NinjaOne API request failed ($Method $Uri). Verify scopes and token validity. Error: $($_.Exception.Message)"
    }
}

function Save-NinjaTokenCache {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$TokenInfo
    )

    # SECURITY NOTE: This uses Windows DPAPI for encryption and is user/machine specific.
    # For cross-platform secure storage, prefer Microsoft.PowerShell.SecretManagement.
    $json = $TokenInfo | ConvertTo-Json -Depth 6 -Compress

    if ($IsWindows) {
        $secure = ConvertTo-SecureString -String $json -AsPlainText -Force
        $encrypted = ConvertFrom-SecureString -SecureString $secure
        Set-Content -Path $Path -Value $encrypted -Encoding UTF8 -NoNewline
    }
    else {
        throw 'DPAPI-based token cache is implemented for Windows only. Use SecretManagement on non-Windows platforms.'
    }

    [pscustomobject]@{ Success = $true; Path = $Path }
}

function Load-NinjaTokenCache {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Token cache file not found: $Path"
    }

    if (-not $IsWindows) {
        throw 'DPAPI-based token cache loader is implemented for Windows only. Use SecretManagement on non-Windows platforms.'
    }

    $encrypted = (Get-Content -LiteralPath $Path -Raw).Trim()
    $secure = ConvertTo-SecureString -String $encrypted
    $plain = [System.Net.NetworkCredential]::new('', $secure).Password
    $token = $plain | ConvertFrom-Json

    $expiresInValue = 0
    $rawExpiresIn = [string]$token.expires_in
    if (-not [int]::TryParse($rawExpiresIn.Trim(), [ref]$expiresInValue)) {
        throw "Token cache is invalid: expires_in value '$rawExpiresIn' is not a valid integer. Delete the cache and authenticate again."
    }

    $createdAtValue = [datetime]::MinValue
    $rawCreatedAt = [string]$token.created_at
    if (-not [datetime]::TryParse($rawCreatedAt.Trim(), [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind, [ref]$createdAtValue)) {
        throw "Token cache is invalid: created_at value '$rawCreatedAt' is not a valid datetime. Delete the cache and authenticate again."
    }

    $script:NinjaTokenInfo = [pscustomobject]@{
        access_token  = [string]$token.access_token
        refresh_token = [string]$token.refresh_token
        token_type    = [string]$token.token_type
        scope         = [string]$token.scope
        expires_in    = $expiresInValue
        created_at    = $createdAtValue
    }

    return $script:NinjaTokenInfo
}

function Get-NinjaTokenInfo {
    [CmdletBinding()]
    param()

    if (-not $script:NinjaTokenInfo) {
        return $null
    }

    return [pscustomobject]@{
        access_token  = [string]$script:NinjaTokenInfo.access_token
        refresh_token = [string]$script:NinjaTokenInfo.refresh_token
        token_type    = [string]$script:NinjaTokenInfo.token_type
        scope         = [string]$script:NinjaTokenInfo.scope
        expires_in    = [int]$script:NinjaTokenInfo.expires_in
        created_at    = [datetime]$script:NinjaTokenInfo.created_at
    }
}

Export-ModuleMember -Function @(
    'New-NinjaOAuthState',
    'Get-NinjaAuthorizationUrl',
    'Start-NinjaOAuthLogin',
    'Wait-NinjaOAuthCallback',
    'Test-NinjaOAuthState',
    'Request-NinjaOAuthToken',
    'Refresh-NinjaOAuthToken',
    'Get-ValidNinjaAccessToken',
    'Invoke-NinjaApiRequest',
    'Save-NinjaTokenCache',
    'Load-NinjaTokenCache',
    'Get-NinjaTokenInfo',
    'Get-MaskedClientId',
    'Get-ClientIdSource'
)
