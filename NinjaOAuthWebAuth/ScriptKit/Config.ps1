# NinjaOne OAuth configuration for Authorization Code Flow
# IMPORTANT: Do not commit real secrets to source control.

# Option 1: Environment variables (recommended)
$NinjaClientId     = $env:NINJA_CLIENT_ID
$NinjaClientSecret = $env:NINJA_CLIENT_SECRET

# Option 2: Hardcode only for local testing (not recommended)
# $NinjaClientId     = 'your-client-id'
# $NinjaClientSecret = 'your-client-secret'

$NinjaRedirectUri = 'http://localhost:8756/callback/'
$NinjaScopes      = @('monitoring', 'management', 'offline_access')

# Default endpoints for CLI sample usage.
# Activity GUI overrides these automatically based on the selected domain dropdown value.
$NinjaAuthUrl  = 'https://eu.ninjarmm.com/oauth/authorize'
$NinjaTokenUrl = 'https://eu.ninjarmm.com/ws/oauth/token'

# Optional token cache file path (DPAPI encrypted payload)
$NinjaTokenCachePath = Join-Path $PSScriptRoot 'ninja-token-cache.json'

# Callback and token timeout settings
$NinjaCallbackTimeoutSeconds = 180
$NinjaHttpTimeoutSeconds     = 60
