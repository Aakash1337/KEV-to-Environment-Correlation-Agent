# KEV Mapper

**KEV-to-Environment Correlation Agent**

A local-first tool that continuously ingests CISA's Known Exploited Vulnerabilities (KEV) catalog, matches them deterministically to your environment, and uses AI to generate actionable remediation guidance.

![Version](https://img.shields.io/badge/version-0.3.0-blue)
![Python](https://img.shields.io/badge/python-3.8+-green)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

## 🎯 Features

- **Automated KEV Ingestion**: Continuously sync CISA's KEV catalog with change tracking
- **Deterministic Matching**: Evidence-based correlation with scanner findings (Nessus, Qualys, etc.)
- **AI-Assisted Remediation**: Claude-powered remediation packet generation with safety guardrails
- **Priority-Based Work Queue**: Intelligent scoring based on asset criticality, exposure, and KEV age
- **Multiple Export Formats**: Markdown, JSON, and CSV exports for integration
- **Web UI + CLI**: Choose your preferred interface
- **Local-First**: All data stored locally, no telemetry
- **Audit Trail**: Complete logging of all operations

## 📋 Prerequisites

- Python 3.8 or higher
- Optional: Anthropic API key (for AI remediation features)

## 🚀 Quick Start

### 1. Installation

```bash
# Clone the repository
cd KEV-to-Environment-Correlation-Agent

# Install dependencies
pip install -r requirements.txt

# Copy example environment file
cp .env.example .env

# Edit .env and add your Anthropic API key (optional)
nano .env
```

### 2. Configure

Edit `config.yaml` to customize settings:

```yaml
database:
  path: "data/kev_mapper.db"

kev:
  source_url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

ai:
  model: "claude-sonnet-4-5-20250929"

prioritization:
  weights:
    asset_criticality: 0.35
    exposure: 0.30
    kev_age: 0.20
    finding_age: 0.15
```

### 3. Initial Setup

```bash
# Sync KEV catalog
python kev_mapper.py sync

# Import your environment data (scanner export or asset inventory)
python kev_mapper.py import-data path/to/nessus_export.csv --type nessus_csv

# Run matching and prioritization
python kev_mapper.py full-sync
```

### 4. Use the Web UI

```bash
# Start the web application
python webapp.py

# Open browser to http://localhost:8000
```

## 📖 Usage Guide

### CLI Commands

#### KEV Management

```bash
# Sync KEV catalog from CISA
python kev_mapper.py sync

# View KEV updates
python kev_mapper.py list-matches --limit 10
```

#### Import Environment Data

```bash
# Import Nessus CSV export
python kev_mapper.py import-data nessus_export.csv --type nessus_csv

# Import Qualys CSV export
python kev_mapper.py import-data qualys_export.csv --type qualys_csv

# Import asset inventory (JSON or CSV)
python kev_mapper.py import-data assets.json --type asset_inventory

# Import SBOM (CycloneDX or SPDX)
python kev_mapper.py import-data sbom.json --type sbom
```

#### Matching and Prioritization

```bash
# Run matching engine
python kev_mapper.py match

# Calculate priority scores
python kev_mapper.py prioritize

# Run full workflow (sync + match + prioritize)
python kev_mapper.py full-sync
```

#### View and Analyze Matches

```bash
# List open matches
python kev_mapper.py list-matches --status open --limit 20

# Show detailed match information
python kev_mapper.py show 123

# Generate AI remediation packet
python kev_mapper.py remediate 123
```

#### Export

```bash
# Export to Markdown
python kev_mapper.py export --format markdown --limit 50

# Export to JSON
python kev_mapper.py export --format json --limit 50 --output report.json

# Export to CSV
python kev_mapper.py export --format csv --limit 100
```

### Web Interface

The web UI provides:

- **Dashboard**: Overview statistics and quick actions
- **Matches Page**: Browse and filter KEV matches
- **Assets Page**: View your asset inventory
- **KEV Updates**: Track new KEV entries

Access at `http://localhost:8000` after starting with `python webapp.py`

## 📂 Data Import Formats

### Asset Inventory CSV/JSON

```csv
hostname,ip,os,criticality,environment,exposure,owner,tags
webserver-01,192.168.1.10,Ubuntu 20.04,high,production,internet_facing,ops,"web,public"
dbserver-01,10.0.1.5,RHEL 8,critical,production,internal_only,dba,"database,sensitive"
```

### Nessus CSV Export

Required columns: `Host`, `IP`, `CVE`, `Plugin ID`, `Name`, `Severity`

### Qualys CSV Export

Required columns: `DNS`, `IP`, `CVE ID`, `Title`, `Severity`

## 🏗️ Architecture

```
KEV Mapper
├── KEV Ingestion       - Fetch and track CISA KEV catalog
├── Environment Import  - Ingest scanner findings and asset inventory
├── Matching Engine     - Deterministic CVE correlation
├── Prioritization      - Score matches based on risk factors
├── AI Assistant        - Generate remediation guidance (Claude API)
├── Exports             - Markdown, JSON, CSV outputs
└── Interfaces          - Web UI + CLI
```

## 🔒 Security & Privacy

- **Local-First**: All data stored in local SQLite database
- **No Telemetry**: No data sent to third parties (except Anthropic API when using AI features)
- **AI Guardrails**: AI cannot execute changes, only draft recommendations
- **Evidence-Based**: All matches require deterministic evidence
- **Audit Logging**: Complete trail of all operations

## 📊 Prioritization Factors

Matches are scored based on:

1. **Asset Criticality** (35%): critical > high > medium > low
2. **Exposure** (30%): internet-facing > vpn-only > internal-only
3. **KEV Age** (20%): Newer KEVs prioritized
4. **Finding Age** (15%): Recently discovered findings prioritized

Customize weights in `config.yaml`

## 🤖 AI Remediation Assistant

The AI assistant (powered by Claude):

- Generates remediation steps based on evidence
- Provides validation commands
- Suggests compensating controls
- Includes rollback guidance
- **Safety**: Cannot execute commands, only drafts for human review

## 🛠️ Development

### Project Structure

```
KEV-to-Environment-Correlation-Agent/
├── src/
│   ├── database/          # SQLAlchemy models and DB management
│   ├── ingestion/         # KEV and environment data import
│   ├── matching/          # Correlation engine
│   ├── prioritization/    # Scoring logic
│   ├── ai/                # AI remediation assistant
│   ├── exports/           # Export formatters
│   ├── web/               # FastAPI web application
│   └── cli/               # Click CLI commands
├── data/                  # Database and local storage
├── imports/               # Place import files here
├── exports/               # Export output directory
├── config.yaml            # Configuration
└── requirements.txt       # Python dependencies
```

### Running Tests

```bash
# Install test dependencies
pip install pytest pytest-cov

# Run tests
pytest tests/
```

## 📝 Release Plan

- **v0.1** ✅ KEV ingestion + diff + store
- **v0.2** ✅ Environment import + matching
- **v0.3** ✅ AI drafting + exports (Current)
- **v1.0** 🔜 Notifications + integrations (Jira, GitHub Issues)

## 🤝 Contributing

Contributions welcome! This is a personal cybersecurity project designed for:

- Solo defenders managing homelabs
- Small organization security teams
- Security researchers and auditors

## 📄 License

MIT License - See LICENSE file for details

## 🙏 Acknowledgments

- CISA for maintaining the KEV catalog
- Anthropic for Claude API
- The cybersecurity community for feedback and support

## 📞 Support

For issues, questions, or feedback:

- GitHub Issues: [Project Issues]
- Documentation: See `/docs` directory
- Examples: See `/examples` directory

## ⚠️ Disclaimer

This tool is for authorized security testing and defensive security operations only. Users are responsible for:

- Ensuring proper authorization before scanning environments
- Complying with all applicable laws and regulations
- Validating AI-generated recommendations before implementation
- Maintaining appropriate backups and change control processes

---

**Built with ❤️ for the defensive security community**
