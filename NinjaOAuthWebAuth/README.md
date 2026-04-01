# NinjaOne OAuth2 Web Authentication (Authorization Code Flow)

This folder contains a complete PowerShell implementation for NinjaOne web authentication using OAuth2 Authorization Code Flow, including refresh token support.

## Suggested file structure

```text
NinjaOAuthWebAuth/
├─ Config.ps1
├─ NinjaOAuth.psm1
├─ Start-NinjaOAuthLogin.ps1
├─ NinjaOne-ActivityFilter-GUI-WebAuth.ps1
└─ README.md
```

## Full setup checklist (NinjaOne + local scripts)

Follow all steps below.

### 1) Configure the NinjaOne client app

In NinjaOne API client app settings:

1. Use a **Web authentication / Authorization Code** style app.
2. Add Redirect URI exactly as:
   - `http://localhost:8756/callback/`
3. Enable scopes required by this project:
   - `Monitoring`
   - `Management`
   - `offline_access` (if your UI shows this separately, enable it so refresh token flow works)
4. Enable allowed grant types:
   - `Authorization Code`
   - `Refresh token`
5. Save and copy:
   - **Client ID**
   - **Client Secret**

> Redirect URI must match exactly (including trailing slash).

### 2) Configure `Config.ps1`

Open `NinjaOAuthWebAuth/Config.ps1` and set:

- `$NinjaClientId`
- `$NinjaClientSecret`
- `$NinjaRedirectUri` (default is `http://localhost:8756/callback/`)
- `$NinjaScopes` (default includes `monitoring`, `management`, `offline_access`)

You can use environment variables:

- `NINJA_CLIENT_ID`
- `NINJA_CLIENT_SECRET`

Also review these optional `Config.ps1` values:

- `$NinjaAuthUrl` and `$NinjaTokenUrl` (used by CLI script; GUI overrides them from dropdown domain)
- `$NinjaTokenCachePath` (token cache file path)
- `$NinjaCallbackTimeoutSeconds` (callback wait timeout)
- `$NinjaHttpTimeoutSeconds` (HTTP request timeout)

### 3) Domain/endpoints behavior (important)

- The **Activity GUI** uses a domain dropdown:
  - `eu.ninjarmm.com`
  - `app.ninjarmm.com`
  - `ca.ninjarmm.com`
  - `oc.ninjarmm.com`
  - `us2.ninjarmm.com`
- The dropdown default is now derived from `$NinjaAuthUrl` in `Config.ps1` (host part), when it matches one of the supported domains.
- After you select a domain and click **Login**, the GUI dynamically builds and uses:
  - `https://<selected-domain>/oauth/authorize`
  - `https://<selected-domain>/ws/oauth/token`
  - API calls to `https://<selected-domain>/...`

So yes: even if EU appears as default in `Config.ps1`, the GUI overrides endpoints from the dropdown selection at runtime.

### 4) Run the CLI sample login script (optional)

From repository root:

```powershell
pwsh -File .\NinjaOAuthWebAuth\Start-NinjaOAuthLogin.ps1
```

Optional token cache:

```powershell
pwsh -File .\NinjaOAuthWebAuth\Start-NinjaOAuthLogin.ps1 -UseTokenCache
```

Notes:
- If `-SampleApiUri` is not provided, it automatically targets `/v2/organizations` on the host from `$NinjaTokenUrl`.

### 5) Run the Activity GUI (web-auth integrated)

From repository root:

```powershell
powershell -ExecutionPolicy Bypass -File .\NinjaOAuthWebAuth\NinjaOne-ActivityFilter-GUI-WebAuth.ps1
```

From inside `NinjaOAuthWebAuth` folder:

```powershell
powershell -ExecutionPolicy Bypass -File .\NinjaOne-ActivityFilter-GUI-WebAuth.ps1
```

### 6) GUI usage steps

Column header filters are available directly in the results grid and apply client-side to the currently loaded rows.

1. Choose the correct tenant domain in dropdown.
2. Click **Login**.
3. First login: complete browser sign-in/consent.
4. Next logins: GUI first tries the local token cache (`$NinjaTokenCachePath`) and only opens the browser again when cache/refresh token is invalid or revoked.
5. In GUI, set date/type filters.
6. Optional: choose an organization in **Organization (optional)**.
7. Optional: use the filter inputs in each result-grid column header to live-filter visible rows (Activity ID, Activity Time, Device ID, Hostname, Type, Status, Severity, Details).
8. Click **Search**.
9. If only organization is selected, the GUI resolves organization devices from `/v2/devices` (paged) and queries activities per matched device.
10. Optional: **Export CSV** or **Copy Rows**.

## OAuth flow (technical summary)

1. Generate cryptographically random `state`.
2. Build authorize URL with `response_type=code`, `client_id`, `redirect_uri`, `scope`, `state`.
3. Open browser and authenticate.
4. Capture callback (`code`, `state`).
5. Validate `state`.
6. Exchange code at `/ws/oauth/token` using form-urlencoded body:
   - `grant_type=authorization_code`
   - `client_id`
   - `client_secret`
   - `code`
   - `redirect_uri`
7. Refresh when needed with:
   - `grant_type=refresh_token`
   - `client_id`
   - `client_secret`
   - `refresh_token`

## ScriptKit (build your own scripts)

Want a shareable starter folder for building scripts on top of this Web OAuth login? See: `NinjaOAuthWebAuth/ScriptKit/README.md`.

## Function overview

- `New-NinjaOAuthState`
- `Get-NinjaAuthorizationUrl`
- `Start-NinjaOAuthLogin`
- `Wait-NinjaOAuthCallback`
- `Test-NinjaOAuthState`
- `Request-NinjaOAuthToken`
- `Refresh-NinjaOAuthToken`
- `Get-ValidNinjaAccessToken`
- `Invoke-NinjaApiRequest`
- `Save-NinjaTokenCache`
- `Load-NinjaTokenCache`

## Security notes

- Never print/log `client_secret`, `access_token`, or `refresh_token`.
- Never commit secrets to source control.
- Do not store tokens in plain text in production.
- Current cache helper is Windows DPAPI (`ConvertFrom-SecureString`), machine/user scoped.
- For cross-platform secret storage, use `Microsoft.PowerShell.SecretManagement`.
- Keep redirect callback local (`localhost` / `127.0.0.1`).

## Troubleshooting

- **File path error on `-File`**: use the command variant matching your current folder (root vs `NinjaOAuthWebAuth`).
- **No callback received**: verify redirect URI, local port, firewall, and app redirect config.
- **Unable to find type [System.Web.HttpUtility]**: update to the latest version of this repo; callback parsing is now System.Web-independent.
- **Invalid state**: retry login; stale browser callback can cause mismatch.
- **Token exchange fails**: ensure Authorization Code flow is enabled and redirect URI matches exactly.
- **`resultCode: Client app not exist` during token exchange**: your selected tenant domain does not contain that client app, or the Client ID/secret are from a different tenant. Re-check the GUI domain dropdown and confirm the OAuth app exists in that exact NinjaOne tenant.
- **If login opens but token exchange still fails after creating a new client app**: verify you created a **Web authentication / Authorization Code** app (not API Services client-credentials only), and that the app redirect URI exactly matches `http://localhost:8756/callback/`.
- **NinjaOne UI gotcha (very common)**: your app must be created as **Web Authentication** (confidential client) with Authorization Code flow. In some UI variants, `Authorization Code` is not shown anymore after save even though it is part of the app type—if unsure, recreate the app with Web platform and click **Update** before testing again.
- **Verify which Client ID is actually loaded**: the GUI/CLI now logs a masked `clientId` and source (`config-file` vs `NINJA_CLIENT_ID`). If `NINJA_CLIENT_ID` is set, it can override your expected credentials.
- **No refresh token**: ensure refresh grant + `offline_access` are allowed.
- **Consent dialog appears every login**: this usually means no reusable refresh token is being loaded (or it was revoked). Ensure `offline_access` + refresh grant are enabled and that the token cache file path in `Config.ps1` is writable for your user.
- **401 API errors**: refresh token may be revoked/expired; log in again.
