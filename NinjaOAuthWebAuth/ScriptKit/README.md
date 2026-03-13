# ScriptKit: Build and share NinjaOne scripts with Web OAuth login

This folder is designed to be **shareable as a standalone package**.
It contains the shared WebAuth script(s), examples, and the required OAuth module/config files so another user can run it without the full repository layout.

---

## Folder contents

- `WebAuth-Common.ps1`
  - `Initialize-NinjaWebAuthSession`
  - `Invoke-NinjaWebAuthApiGet`
- `Example-Get-Organizations.ps1`
- `Example-Get-Devices.ps1`
- `Config.ps1` (local config used by ScriptKit)
- `Dependencies/NinjaOAuth.psm1` (local OAuth module dependency)

---

## Why this is shareable

`WebAuth-Common.ps1` first tries local files:
- `./Config.ps1`
- `./Dependencies/NinjaOAuth.psm1`

If those are not found, it falls back to parent repo files:
- `../Config.ps1`
- `../NinjaOAuth.psm1`

So this folder works in both contexts:
1. inside this repository, and
2. when copied/shared on its own.

---

## Prerequisites

1. A NinjaOne **Web Authentication** client app exists.
2. Redirect URI exactly matches:
   - `http://localhost:8756/callback/`
3. Correct tenant domain is used (one of: `app.ninjarmm.com`, `eu.ninjarmm.com`, `ca.ninjarmm.com`, `oc.ninjarmm.com`, `us2.ninjarmm.com`).
4. PowerShell can open a local HTTP listener on your callback port.

---

## Configure credentials

Edit `ScriptKit/Config.ps1` and set either:
- environment variables (`NINJA_CLIENT_ID`, `NINJA_CLIENT_SECRET`), or
- hardcoded values for local testing.

Do not commit real secrets.

---

## Quick start

### Get organizations

```powershell
pwsh -File .\ScriptKit\Example-Get-Organizations.ps1 -TenantDomain eu.ninjarmm.com
```

### Get devices

```powershell
pwsh -File .\ScriptKit\Example-Get-Devices.ps1 -TenantDomain eu.ninjarmm.com -PageSize 100
```

---

## Create your own script

Create `My-Custom-Report.ps1` in this folder:

```powershell
[CmdletBinding()]
param(
    [string]$TenantDomain = 'eu.ninjarmm.com'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'WebAuth-Common.ps1')

$session = Initialize-NinjaWebAuthSession -TenantDomain $TenantDomain -ShowConfigSummary

$orgs = Invoke-NinjaWebAuthApiGet -Session $session -PathAndQuery '/v2/organizations'
$devices = Invoke-NinjaWebAuthApiGet -Session $session -PathAndQuery '/v2/devices?pageSize=200'

[pscustomobject]@{
    OrganizationCount = @($orgs).Count
    DeviceCount       = @($devices).Count
}
```

---

## Function reference

### `Initialize-NinjaWebAuthSession`

- loads config + module
- builds tenant endpoints
  - `https://<tenant>/oauth/authorize`
  - `https://<tenant>/ws/oauth/token`
- opens browser login
- waits for callback
- exchanges auth code for tokens

Returns a session object used by the API functions in this kit.

### `Invoke-NinjaWebAuthApiGet`

- ensures valid access token (refreshes when needed)
- executes a GET request against your tenant API

Example:

```powershell
$result = Invoke-NinjaWebAuthApiGet -Session $session -PathAndQuery '/v2/organizations'
```

---

## Troubleshooting

### `Client app does not exist`

Check:
- app exists in the exact same tenant domain used by the script
- app type/platform is Web Authentication
- redirect URI exactly matches
- changes were saved in NinjaOne

### Browser opens but callback never completes

Check:
- callback URI and port
- local firewall/policy
- exact redirect URI match

### Wrong client ID used

Use `-ShowConfigSummary` to print the masked client ID and source (config vs environment variable).

---

## Recommended sharing process

When sharing with another team/user, send the entire `ScriptKit` folder with:
- `README.md`
- `WebAuth-Common.ps1`
- `Example-*.ps1`
- `Config.ps1`
- `Dependencies/NinjaOAuth.psm1`

Then they only need to fill in `Config.ps1` and run the examples.
