# DYNAMO

DYNAMO is an external attack surface management and VAPT reconnaissance tool. It runs a configurable pipeline of open source recon tools, correlates their output, scores risk per asset, and presents results in a local dashboard backed by PostgreSQL.
It is intended for authorized security testing, penetration testing engagements, and continuous monitoring of assets you own or have written permission to test.


## What it does

The pipeline runs in two modes.

Quick mode:
- Passive subdomain discovery (subfinder, crt.sh)
- Historical URL collection (gau, wayback)
- Live host probing (httpx)
- Port and service scanning (nmap)
- Correlation and risk scoring

Full mode adds:
- Web crawling (katana)
- Directory fuzzing (ffuf)
- Vulnerability scanning (nuclei)
- JavaScript analysis for leaked secrets and endpoints
- Passive and active VAPT checks (headers, CORS, methods, sensitive files, parameter probes)
- SQL injection testing (sqlmap)

After a scan you can optionally run AI triage on high risk assets using a local Ollama model.

All results are stored in PostgreSQL and shown in a Streamlit dashboard.

## Requirements

- Python 3.10 or newer
- PostgreSQL 13 or newer
- macOS, Linux, or WSL2 on Windows

External tools that must be on PATH:

- subfinder
- httpx
- nmap
- gau
- katana (full mode)
- ffuf (full mode)
- nuclei (full mode)
- sqlmap (full mode)

Ollama is only required for AI enrichment.

## Install

1. Clone the repo and enter it.

    git clone https://github.com/Happy9119/dynamo.git
    cd dynamo

2. Create and activate a virtual environment.

    python3 -m venv .venv
    source .venv/bin/activate
    # Windows: .venv\Scripts\activate

3. Install Python dependencies.

    pip install -r requirements.txt

4. Update environment file.

    .env

   Set DATABASE_URL to point at your PostgreSQL instance. The default is:

    postgresql+psycopg://localhost/dynamo_recon

5. Create the database.

    createdb dynamo_recon

6. Initialize tables.

    python init_db.py
    python update_db.py

7. Install the external tools. On macOS:

    brew install nmap ffuf
    brew install go
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest
    go install github.com/projectdiscovery/katana/cmd/katana@latest
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    go install github.com/lc/gau/v2/cmd/gau@latest
    pip install sqlmap
    nuclei -update-templates

8. Optional, for AI enrichment:

    curl -fsSL https://ollama.com/install.sh | sh
    ollama pull phi3:mini
    ollama serve

## Usage

Run a quick scan:

    python main.py example.com

Run a full scan:

    python main.py example.com --full

Run a scan and then run AI enrichment in the same call:

    python main.py example.com --full --enrich

Force a new scan instead of resuming an interrupted one:

    python main.py example.com --fresh

Run AI enrichment separately after a scan:

    python enrich.py --scan-id 42
    python enrich.py --domain example.com
    python enrich.py --all

Start the dashboard:

    streamlit run dashboard/Dashboard.py

Open http://localhost:8501 in a browser.

## Configuration

Environment variables are read from `.env`. See `.env.example` for the full list.

The most important ones:

- `DATABASE_URL`: PostgreSQL connection string
- `OLLAMA_URL`: where Ollama listens. Default `http://localhost:11434/api/generate`
- `TRIAGE_MODEL`: fast model for quick analysis. Default `phi3:mini`
- `DEEP_MODEL`: larger model for detailed analysis. Default `mistral`
- `AI_RISK_THRESHOLD`: minimum risk score for an asset to be sent for AI analysis. Default 20

Binary paths can be overridden with `SUBFINDER_BIN`, `HTTPX_BIN`, `NMAP_BIN`, `GAU_BIN`, `KATANA_BIN`, `NUCLEI_BIN`, `FFUF_BIN`, `SQLMAP_BIN`.

Model selection can also be changed at runtime from the Launchpad page in the dashboard.

## How it works

Phase 1, passive discovery. subfinder, crt.sh, gau, and wayback run in parallel to collect subdomains and historical URLs.

Phase 2, live probing. httpx checks which hosts are up and collects titles, technology stack, and status codes.

Phase 3, port scanning. nmap runs against each resolved IP and reports open ports and service versions.

Phases 4 to 7, full mode only. katana crawls, ffuf fuzzes directories, nuclei scans for known issues, JavaScript analysis looks for leaked secrets and endpoints, and sqlmap tests for SQL injection.

Phase 8, correlation and storage. Results are merged per asset, risk is scored, and everything is written to PostgreSQL.

Phase 9, optional. High risk assets are sent to a local Ollama model to produce attack path suggestions.

See `ARCHITECTURE.md` for a detailed map of the codebase.

## Project structure

    ai/          Ollama prompt templates
    config/      database and tool configuration
    core/        pipeline, correlation, risk scoring, AI engine
    modules/     one runner per external tool
    schemas/     Pydantic models
    storage/     SQLAlchemy models and persistence
    vapt/        passive and active VAPT checks
    dashboard/   Streamlit UI
    data/cves/   static CVE map

## Dashboard

Pages:

- Dashboard: top level summary across all targets
- Targets: per domain drill down with findings, assets, timeline, scan diff, and PDF reports
- Exposure: cross domain findings browser
- Launchpad: start scans, run AI enrichment, change model settings, view scan history, admin tools
- Scan Output: browse and download raw artifacts per scan

## Legal

DYNAMO runs invasive tools in full mode, including nuclei, ffuf, and sqlmap. Use it only against systems you own or have explicit written permission to test. Unauthorized use may be illegal in your jurisdiction.

## Contributing

Bug reports and pull requests are welcome.

## License

MIT. See `LICENSE` for details.
