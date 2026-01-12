# KEV Mapper - Detailed Usage Guide

## Table of Contents

1. [Getting Started](#getting-started)
2. [Configuration](#configuration)
3. [Workflow](#workflow)
4. [CLI Reference](#cli-reference)
5. [Web UI Guide](#web-ui-guide)
6. [Import Formats](#import-formats)
7. [Export Options](#export-options)
8. [Best Practices](#best-practices)

## Getting Started

### First Time Setup

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Set up environment:**
   ```bash
   cp .env.example .env
   # Edit .env and add your Anthropic API key
   ```

3. **Initialize database:**
   ```bash
   # The database is created automatically on first run
   python kev_mapper.py sync
   ```

### Daily Workflow

```bash
# 1. Sync latest KEV data
python kev_mapper.py sync

# 2. Import new scanner results (if available)
python kev_mapper.py import-data latest_scan.csv --type nessus_csv

# 3. Run full analysis
python kev_mapper.py full-sync

# 4. View top priorities
python kev_mapper.py list-matches --limit 20

# 5. Export work queue
python kev_mapper.py export --format markdown
```

## Configuration

### config.yaml Structure

```yaml
database:
  path: "data/kev_mapper.db"  # SQLite database location

kev:
  source_url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
  github_mirror: "https://raw.githubusercontent.com/cisagov/KEV/main/known_exploited_vulnerabilities.json"
  sync_interval_hours: 24  # How often to sync (for scheduled runs)

ai:
  provider: "anthropic"
  model: "claude-sonnet-4-5-20250929"
  max_tokens: 4096
  temperature: 0.3  # Lower = more focused, higher = more creative

prioritization:
  weights:
    asset_criticality: 0.35  # Weight for asset criticality score
    exposure: 0.30           # Weight for exposure level
    kev_age: 0.20           # Weight for KEV freshness
    finding_age: 0.15       # Weight for finding age

  criticality_scores:
    critical: 10
    high: 7
    medium: 4
    low: 2

  exposure_scores:
    internet_facing: 10
    vpn_only: 5
    internal_only: 2

reporting:
  default_export_path: "exports/"
  include_evidence: true
  max_items_per_report: 50

audit:
  enabled: true
  log_path: "data/audit.log"
```

### Environment Variables

Create a `.env` file:

```bash
# Required for AI features
ANTHROPIC_API_KEY=sk-ant-...

# Optional overrides
DATABASE_PATH=data/kev_mapper.db
```

## Workflow

### Complete Workflow Example

```bash
# Step 1: Sync KEV catalog
python kev_mapper.py sync
# Output: "KEV sync completed successfully"
# Result: Latest KEV entries stored in database

# Step 2: Import your environment data
# Option A: Scanner export (Nessus, Qualys)
python kev_mapper.py import-data /path/to/nessus_export.csv --type nessus_csv

# Option B: Asset inventory
python kev_mapper.py import-data examples/sample_asset_inventory.csv --type asset_inventory

# Step 3: Run matching to correlate KEV with your environment
python kev_mapper.py match
# Output: "Matching completed: X new matches"

# Step 4: Calculate priority scores
python kev_mapper.py prioritize
# Output: "Prioritization completed successfully"

# Step 5: View your work queue
python kev_mapper.py list-matches --status open --limit 20

# Step 6: Generate remediation for high-priority items
python kev_mapper.py remediate 1  # Replace 1 with actual match ID

# Step 7: Export for sharing/tracking
python kev_mapper.py export --format markdown --limit 50
```

### Automated Workflow (Cron/Scheduled Task)

Create a script `daily_kev_sync.sh`:

```bash
#!/bin/bash
cd /path/to/KEV-to-Environment-Correlation-Agent

# Run full sync
python kev_mapper.py full-sync

# Export top 20 items
python kev_mapper.py export --format markdown --limit 20 --output daily_report.md

# Optional: Email the report
# mail -s "Daily KEV Report" security@example.com < exports/daily_report.md
```

Schedule with cron:
```
# Run daily at 6 AM
0 6 * * * /path/to/daily_kev_sync.sh
```

## CLI Reference

### Global Options

```bash
--config PATH  # Specify alternate config file (default: config.yaml)
```

### Commands

#### `sync`
Sync KEV catalog from CISA.

```bash
python kev_mapper.py sync
```

**Output:**
- Number of entries synced
- New entries added
- Updated entries

#### `import-data`
Import environment data from various sources.

```bash
python kev_mapper.py import-data FILE --type TYPE
```

**Options:**
- `FILE`: Path to import file
- `--type`: File type (nessus_csv, qualys_csv, asset_inventory, sbom)

**Examples:**
```bash
python kev_mapper.py import-data scan.csv --type nessus_csv
python kev_mapper.py import-data assets.json --type asset_inventory
```

#### `match`
Run matching engine to correlate KEV with environment.

```bash
python kev_mapper.py match [--cve CVE-ID]
```

**Options:**
- `--cve`: Match specific CVE(s) only (can be specified multiple times)

**Example:**
```bash
python kev_mapper.py match --cve CVE-2024-1234
```

#### `prioritize`
Calculate priority scores for all open matches.

```bash
python kev_mapper.py prioritize
```

#### `list-matches`
List matches with filtering and pagination.

```bash
python kev_mapper.py list-matches [OPTIONS]
```

**Options:**
- `--limit N`: Show N matches (default: 20)
- `--status STATUS`: Filter by status (open, mitigated, false_positive)

**Examples:**
```bash
python kev_mapper.py list-matches --status open --limit 50
python kev_mapper.py list-matches --status mitigated
```

#### `show`
Show detailed information about a specific match.

```bash
python kev_mapper.py show MATCH_ID
```

**Example:**
```bash
python kev_mapper.py show 123
```

#### `remediate`
Generate AI remediation packet for a match.

```bash
python kev_mapper.py remediate MATCH_ID
```

**Example:**
```bash
python kev_mapper.py remediate 123
```

#### `export`
Export matches to file.

```bash
python kev_mapper.py export [OPTIONS]
```

**Options:**
- `--format FORMAT`: Export format (markdown, json, csv)
- `--limit N`: Maximum matches to export
- `--output FILE`: Output filename

**Examples:**
```bash
python kev_mapper.py export --format markdown --limit 50
python kev_mapper.py export --format json --output report.json
python kev_mapper.py export --format csv --limit 100
```

#### `full-sync`
Run complete workflow (sync + match + prioritize).

```bash
python kev_mapper.py full-sync
```

## Web UI Guide

### Starting the Web Interface

```bash
python webapp.py
```

Access at: `http://localhost:8000`

### Dashboard

- **Statistics**: Overview of KEV entries, assets, and matches
- **Quick Actions**:
  - Sync KEV
  - Run Matching
  - Run Prioritization
  - View Matches

### Matches Page

- Browse all matches with sorting and filtering
- Filter by status (open, mitigated, false positive)
- Export to JSON or CSV
- Click any match to view details

### Assets Page

- View all assets in your environment
- Filter by criticality, environment, exposure
- See matches per asset

### KEV Updates Page

- Track new KEV entries
- View KEV entry details
- See which KEVs affect your environment

### API Endpoints

The web app exposes a REST API:

```
GET  /api/stats                    - Dashboard statistics
GET  /api/matches                  - List matches
GET  /api/matches/{id}             - Get match details
POST /api/sync                     - Trigger KEV sync
POST /api/match                    - Trigger matching
POST /api/prioritize               - Trigger prioritization
POST /api/matches/{id}/remediate   - Generate remediation
POST /api/matches/{id}/status      - Update match status
GET  /api/export/{format}          - Export data
```

## Import Formats

### Asset Inventory

**CSV Format:**
```csv
hostname,ip,os,criticality,environment,exposure,owner,tags
server-01,10.0.1.5,Ubuntu 20.04,high,production,internet_facing,ops,"web,public"
```

**JSON Format:**
```json
{
  "assets": [
    {
      "hostname": "server-01",
      "ip": "10.0.1.5",
      "os": "Ubuntu 20.04",
      "criticality": "high",
      "environment": "production",
      "exposure": "internet_facing",
      "owner": "ops",
      "tags": ["web", "public"]
    }
  ]
}
```

**Fields:**
- `hostname`: (required) Asset hostname
- `ip`: IP address
- `os`: Operating system
- `criticality`: critical, high, medium, low
- `environment`: production, development, staging, test
- `exposure`: internet_facing, vpn_only, internal_only
- `owner`: Asset owner/team
- `tags`: Array or comma-separated list of tags

### Nessus CSV Export

Export from Nessus in CSV format with these columns:
- Host
- IP
- CVE
- Plugin ID
- Name
- Severity
- Solution

### Qualys CSV Export

Export from Qualys with these columns:
- DNS
- IP
- CVE ID
- Title
- Severity

## Export Options

### Markdown Export

Produces human-readable remediation packets:

```markdown
# Remediation Packet: CVE-2024-1234

**Priority Score:** 85.2/100

## Vulnerability Details
- CVE ID: CVE-2024-1234
- Product: Apache Tomcat
...

## AI-Generated Remediation
1. Update to version X.Y.Z
2. Restart service
3. Verify with: ...
```

### JSON Export

Machine-readable format for integration:

```json
{
  "generated_at": "2024-01-12T10:00:00Z",
  "total_matches": 25,
  "matches": [
    {
      "match_id": 1,
      "cve_id": "CVE-2024-1234",
      "priority_score": 85.2,
      ...
    }
  ]
}
```

### CSV Export

Spreadsheet-friendly format:

```csv
match_id,cve_id,product,hostname,priority_score,status
1,CVE-2024-1234,Apache Tomcat,server-01,85.2,open
```

## Best Practices

### Regular Operations

1. **Daily Sync**: Run `full-sync` daily to stay current
2. **Import Fresh Scans**: Import new scanner results as they're available
3. **Review Top Items**: Focus on top 10-20 priority matches
4. **Mark Progress**: Update match status as items are remediated

### Asset Management

1. **Keep Inventory Current**: Update asset inventory regularly
2. **Tag Appropriately**: Use tags for grouping (team, function, compliance scope)
3. **Set Correct Criticality**: Accurate criticality improves prioritization
4. **Update Exposure**: Ensure exposure levels reflect reality

### AI Remediation

1. **Always Review**: AI recommendations are drafts, not gospel
2. **Validate Commands**: Test validation commands in non-prod first
3. **Check Evidence**: Ensure recommendations match your environment
4. **Iterate**: Regenerate if recommendations miss the mark

### Security

1. **Protect API Keys**: Keep .env file secure, never commit to git
2. **Secure Database**: Restrict access to data/ directory
3. **Review Exports**: Sanitize exports before sharing externally
4. **Audit Logs**: Periodically review audit.log for anomalies

### Performance

1. **Incremental Imports**: Import only new/changed data when possible
2. **Limit Exports**: Export only what you need
3. **Schedule Heavy Operations**: Run full-sync during off-hours
4. **Clean Old Data**: Periodically archive old matches

## Troubleshooting

### Common Issues

**Issue: KEV sync fails**
- Check internet connectivity
- Try GitHub mirror: Edit config.yaml to use github_mirror
- Verify firewall rules allow HTTPS

**Issue: Import fails**
- Verify file format matches expected columns
- Check for encoding issues (use UTF-8)
- Look for malformed CSV (quotes, commas in data)

**Issue: No matches found**
- Ensure CVE IDs in findings match KEV format (CVE-YYYY-NNNNN)
- Check that you've imported both KEV and environment data
- Verify findings have CVE_ID populated

**Issue: AI remediation fails**
- Check ANTHROPIC_API_KEY in .env
- Verify API key has sufficient credits
- Check network connectivity to api.anthropic.com

### Getting Help

- Check logs in `data/audit.log`
- Review error messages carefully
- Consult PDR.txt for design rationale
- Open GitHub issue with logs and context

---

For more information, see README.md and PDR.txt
