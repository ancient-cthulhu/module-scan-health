# Veracode Bulk Scan Health Report

Identify errors in packaged SAST applications at scale. Iterates over all application profiles, pulls prescan module data via the Veracode XML APIs, and outputs one row per module with the raw platform-reported issues (missing PDBs, debug symbols, fatal errors, unsupported compilers, and more).

---

## How It Works

`script.py` connects to the Veracode REST and XML APIs and:

1. Fetches all application profiles (via REST API)
2. Processes applications concurrently, each worker thread gets its own HTTP session
3. For each app, retrieves the latest build and pulls prescan results with module-level issue details
4. Falls back to the detailed report for published scans where prescan data is no longer available
5. Optionally checks sandbox builds under each app
6. Writes a CSV (and optional JSON) with one row per module, verdicts, and raw platform issue strings

All API calls are read-only. Rate limiting is built in.

---

## Quickstart

### Export all apps

```bash
python script.py
```

Writes `scan_health_report.csv` to the current directory.

### Filter by application name

```bash
python script.py --app-name-filter "MyApp" --verbose
```

### Test with a small batch

```bash
python script.py --max-apps 5 --verbose
```

### Include sandbox builds

```bash
python script.py --include-sandboxes --verbose
```

### European region with SSL inspection

```bash
python script.py --region european --ca-cert /path/to/corp-ca.pem --verbose
```

### Large portfolio with higher throughput

```bash
python script.py --max-workers 20 --rate-limit 20 --verbose
```

---

## Requirements

```bash
pip install requests veracode-api-signing
```

Python 3.9+

---

## Credentials

Requires one of:
- **Human User Account** with **Reviewer** or **Security Lead** role

The `getprescanresults.do` endpoint requires the Reviewer or Security Lead role to return full issue details. Lower roles (e.g. Submitter) may return module elements but with issue data stripped.

```ini
# Windows: C:\Users\<username>\.veracode\credentials
# Mac/Linux: ~/.veracode/credentials

[default]
veracode_api_key_id = YOUR_API_KEY_ID
veracode_api_key_secret = YOUR_API_KEY_SECRET
```

Or via environment variables:

```bash
export VERACODE_API_KEY_ID=your_api_id
export VERACODE_API_KEY_SECRET=your_api_secret
```

---

## Command-Line Reference

### Filtering

| Flag | Default | Description |
|------|---------|-------------|
| `--app-name-filter` | - | Only include apps whose name contains this text (case-insensitive) |
| `--max-apps` | - | Stop after N apps (for testing) |
| `--include-sandboxes` | `False` | Also check the latest sandbox builds under each app |
| `--stale-days` | `90` | Days without a scan before flagging as stale |

### Output

| Flag | Default | Description |
|------|---------|-------------|
| `--output-csv` | `scan_health_report.csv` | CSV output file path |
| `--output-json` | - | Optional JSON output file path |

### Region / Network

| Flag | Default | Description |
|------|---------|-------------|
| `--region` | `commercial` | `commercial` or `european` |
| `--ca-cert` | - | Path to custom CA certificate bundle (.pem). Required behind SSL inspection devices (e.g. Zscaler). |

### Logging

| Flag | Default | Description |
|------|---------|-------------|
| `--verbose` | `False` | Print progress per app (which API step succeeded, module counts) |
| `--debug` | `False` | Dump raw XML API responses (for troubleshooting parsing issues) |

### Performance

| Flag | Default | Description |
|------|---------|-------------|
| `--max-workers` | `5` | Concurrent threads for parallel processing |
| `--rate-limit` | `4.0` | Max API requests per second across all threads (token bucket) ||

---

## HTML Viewer

The companion `scan_health_viewer.html` provides a visual interface for the CSV output:

1. Open `scan_health_viewer.html` in a browser
2. Drop the CSV file onto the page (supports both comma and tab-separated files)
3. Use the filters, search, and sortable columns to explore the data

Features: stat cards with counts by verdict, issue breakdown bar chart (click to filter), verdict filter buttons, dependency toggle, text search across all columns, expandable long issue text. All processing happens client-side.

---

## SSL Inspection (Corporate Proxy)

Pass your corporate CA certificate via `--ca-cert`. If it's DER-encoded (`.cer`), convert first:

```bash
openssl x509 -inform DER -in corp-ca.cer -out corp-ca.pem
python script.py --ca-cert /path/to/corp-ca.pem
```

---

## Output Files

### CSV Columns

One row per module. Apps that could not be analyzed get a single row with the Error column populated.

| Column | Description |
|--------|-------------|
| Application | Application name from Veracode profile |
| App ID | Numeric application ID |
| Business Unit | Business unit from the application profile |
| Scan Context | `Policy` for the top-level scan, `Sandbox: <name>` for sandbox scans |
| Build ID | Build ID of the latest scan |
| Last Scan | Date of the last completed scan (YYYY-MM-DD) |
| Days Since Scan | Days since the last scan was published |
| Module | Module name as reported by the platform |
| Platform | Compiler / OS / architecture string (e.g. `JVM / Java J2SE 8 / JAVAC_8`) |
| Size | Module size as reported by prescan |
| Status | Prescan status (e.g. `OK`, `Support Issue - 1 File`, `JSP Compilation Errors`) |
| Is Dependency | `True` if the module is a third-party dependency, `False` if first-party |
| Fatal Errors | `True` if the module has fatal prescan errors that prevent scanning |
| Verdict | `PASS` (no issues), `WARNING` (non-fatal issues), `FAIL` (fatal errors), `ERROR` (could not analyze) |
| Issues | Raw issue strings from the platform, semicolon-separated. Exactly what Veracode reports. |
| Error | Populated when the app/module could not be analyzed (e.g. no builds, API error) |

### JSON Output

When `--output-json` is specified, writes the same data as a JSON array of objects with the same keys as the CSV columns.

### Verdict Logic

| Verdict | Condition |
|---------|-----------|
| FAIL | Module has `has_fatal_errors="true"` |
| WARNING | Module has `<issue>` or `<file_issue>` children, or the status field contains issue text |
| PASS | No issues detected |
| ERROR | Could not retrieve data for this app (no builds, API error, permissions) |

---

## Troubleshooting

| Error | Fix |
|-------|-----|
| 401/403 | Check credentials file and API role (Reviewer or Security Lead required) |
| 0 apps returned | Service accounts see all apps; user accounts only see assigned teams |
| Modules returned but no issues | API account needs Reviewer or Security Lead role. Submitter role returns modules but strips issue details. |
| `SSLError: certificate verify failed` | Use `--ca-cert /path/to/corp-ca.pem` |
| `handshake_failure` | Veracode requires TLS 1.2+; check your proxy supports it |
| "No builds found" | App has never been scanned or all builds were deleted |
| "No modules found" | Prescan data expired and detailed report unavailable. Re-scan the app to refresh. |
| Last Scan / Days Since Scan empty | The REST API `last_completed_scan_date` or the build's `policy_updated_date` was not set |
| All rows show PASS with no issues | Likely a permissions issue - see "Modules returned but no issues" above |

---

## Data Sources

The script uses a 3-step fallback to get the most complete module data available:

1. `getprescanresults.do` without `build_id` - lets the API return the most recent prescan-eligible build. Has the richest data: module issues, file issues, fatal errors, PDB warnings.
2. `getprescanresults.do` with explicit `build_id` from the build list - in case step 1 picks a different build.
3. `detailedreport.do` - fallback for published scans where prescan data has been cleared. Returns module names, compilers, and architecture but not prescan issue details.

---

## API Calls

All calls are read-only.

| API | Type | Purpose |
|-----|------|---------|
| `GET /appsec/v1/applications` | REST | List all application profiles (paginated) |
| `getbuildlist.do` | XML | Get builds per app (latest first) |
| `getbuildinfo.do` | XML | Get scan status, dates, engine version |
| `getprescanresults.do` | XML | Get module-level prescan issues (primary data source) |
| `detailedreport.do` | XML | Get module info from published scans (fallback) |
| `getsandboxlist.do` | XML | List sandboxes per app (when `--include-sandboxes` is used) |

---

**Note:** This is a community tool and is not officially supported by Veracode.
