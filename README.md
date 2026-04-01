# NinjaOne Activity Filter GUI

Standalone PowerShell/WPF GUI to query NinjaOne activities, filter by date/type/organization, use per-column header filters in the result grid, and export/copy results.

## Use case
If you manage a large environment (for example **18,196 devices**) and NinjaOne CSV export/filtering is currently practical only at day-level granularity, this GUI helps you narrow activity data down to **minute-level windows**.

That makes it easier to investigate spikes, incidents, or audit trails without manually sifting through thousands of same-day events.

<img width="1204" height="751" alt="afbeelding" src="https://github.com/user-attachments/assets/bc898643-c129-4448-8440-431bb356c5ab" />
(Screenshot is from the WebAuth version of the script)

## Features
- OAuth connect to NinjaOne tenant
- Filter by:
  - `After` / `Before` date
  - multiple Activity Types
  - optional Organization
  - per-column header filters in the result grid (`Activity ID`, `Activity Time`, `Device ID`, `Hostname`, `Type`, `Status`, `Severity`, `Details`)
- Result grid columns:
  - Activity ID
  - Activity Time
  - Device ID
  - Hostname
  - Type
  - Status
  - Severity
  - Details
- Export to CSV with the same columns as the GUI
- Copy selected/all rows to clipboard

## Requirements
- Windows PowerShell 5.1+
- Network access to your NinjaOne tenant
- Valid NinjaOne API credentials (Client ID + Secret)

## Usage
1. Open PowerShell.
2. Run the script:
   ```powershell
   . .\NinjaOne-ActivityFilter-GUI.ps1
   ```
3. Fill in:
   - Domain (e.g. `eu.ninjarmm.com`)
   - Client ID
   - Secret
4. Click **Connect**.
5. Choose date range and one or more Activity Types.
6. (Optional) Select an `Organization`.
7. (Optional) If only Organization is set, the script resolves organization devices from `/v2/devices` (paged) and queries activity per matching device.
8. (Optional) Use the filter boxes in the column headers to live-filter visible results (per column, without extra API calls).
9. Click **Search**.
10. Use **Export CSV** or **Copy Rows** if needed.

## Notes
- Client ID and Secret are masked in the UI.
- Organization filtering is applied by matching device organization fields (`organizationId` / `orgId` / `organization.id`) and querying device activities for the matched set.
- Date boundaries are also enforced client-side on returned activity data.
