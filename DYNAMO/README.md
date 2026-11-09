╔══════════════════════════════════════════════════════════════════╗
║                        DYNAMO — README                           ║
║      AI-Powered EASM / VAPT Reconnaissance Engine                ║
╚══════════════════════════════════════════════════════════════════╝

DYNAMO merges the classic AI-enabled recon engine with the phases
from VAPT_AUTO_RECON_v6.sh into a single Python-first pipeline:

    Phase 1  subfinder ‖ crt.name ‖ gau ‖ wayback
    Phase 2  httpx live probing
    Phase 3  nmap port scanning (parallel per IP)
    Phase 4  katana crawling                     [full mode only]
    Phase 5  ffuf directory fuzzing              [full mode only]
    Phase 6  nuclei vulnerability scanning       [full mode only]
    Phase 7  sqlmap SQLi testing                 [full mode only]
    Phase 8  correlate → risk → AI → DB → Dashboard

Two run modes:
    quick  →  phases 1-3 + 8              (fast, ~2-5 min for small targets)
    full   →  phases 1-8                  (thorough, 15-60+ min)


────────────────────────────────────────────────────────────────────
1. PREREQUISITES
────────────────────────────────────────────────────────────────────

Hardware / OS
    - macOS or Linux (Windows WSL2 also works)
    - Python 3.10+
    - PostgreSQL 13+ running locally (or a remote URL)

CLI tools (must be in PATH)
    subfinder   https://github.com/projectdiscovery/subfinder
    httpx       https://github.com/projectdiscovery/httpx
    nmap        https://nmap.org/download
    gau         https://github.com/lc/gau
    katana      https://github.com/projectdiscovery/katana        (full)
    nuclei      https://github.com/projectdiscovery/nuclei        (full)
    ffuf        https://github.com/ffuf/ffuf                      (full)
    sqlmap      https://sqlmap.org                                (full)

    Quick install on macOS:
        brew install nmap
        brew install go
        go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
        go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
        go install -v github.com/projectdiscovery/katana/cmd/katana@latest
        go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
        go install -v github.com/lc/gau/v2/cmd/gau@latest
        brew install ffuf
        pip install sqlmap
        nuclei -update-templates

    Ollama (for the AI layer):
        curl -fsSL https://ollama.com/install.sh | sh
        ollama pull phi3:mini          # or any model you prefer
        ollama serve                   # runs on http://localhost:11434

Quick-only users can omit katana, nuclei, ffuf, sqlmap — DYNAMO skips
those phases automatically if the binaries aren't found.


────────────────────────────────────────────────────────────────────
2. INSTALL
────────────────────────────────────────────────────────────────────

    # 1) create + activate a virtualenv
    python3 -m venv .venv
    source .venv/bin/activate            # Windows: .venv\Scripts\activate

    # 2) install Python dependencies
    pip install -r requirements.txt

    # 3) copy and edit environment config
    cp .env.example .env
    # open .env and set DATABASE_URL + OLLAMA_MODEL

    # 4) create the PostgreSQL database
    createdb dynamo_recon
    # or, if it already exists, skip this step

    # 5) initialise DYNAMO's tables
    python init_db.py

    # 6) sync any new columns (safe to run repeatedly)
    python update_db.py


────────────────────────────────────────────────────────────────────
3. RUN THE PIPELINE (CLI)
────────────────────────────────────────────────────────────────────

    # quick mode
    python main.py example.com

    # full mode
    python main.py example.com --full

    # interactive
    python main.py


────────────────────────────────────────────────────────────────────
3b. AI ENRICHMENT (deferred)
────────────────────────────────────────────────────────────────────

Scans no longer call the LLM inline. AI is a separate pass you run
after a scan finishes:

    # by scan
    python enrich.py --scan-id 42

    # by domain
    python enrich.py --domain example.com

    # everything pending
    python enrich.py --all

    # with a different threshold
    python enrich.py --all --risk-min 40 --limit 20

You can also trigger it from the UI: Launchpad → AI Enrichment tab. 

Why deferred?
  Ollama inference takes 5-30s per asset. On a scan with many
  high-risk assets, inline AI added minutes of dead time at the
  end of every scan. Deferring lets scans finish fast while you
  run enrichment on your own schedule.

The CLI prints a live phase-by-phase log. Example:

    [+] Starting DYNAMO scan: example.com (mode=full)
    [*] Phase 1 — passive discovery (subfinder ‖ crt ‖ gau ‖ wayback)
        subfinder=42 crt=18 gau=132 wayback=2140 unique_subdomains=45
    [*] Phase 2 — httpx live probing
        live assets=31
    ...


────────────────────────────────────────────────────────────────────
4. RUN THE DASHBOARD
────────────────────────────────────────────────────────────────────

    streamlit run dashboard/Dashboard.py

Then open http://localhost:8501 in a browser.

Sidebar controls
    - Domain filter (scopes every page to one apex)
    - Active-only toggle
    - Search (host / title)
    - Refresh button

Pages
    Dashboard             dashboard/Dashboard.py
    Exposure              dashboard/pages/1_Exposure.py
    Targets               dashboard/pages/2_Targets.py
    Launchpad             dashboard/pages/3_Launchpad.py

Scans are launched from Launchpad → Scan.
AI enrichment runs from Launchpad → AI Enrichment (or `python enrich.py`).

All pages read from the same PostgreSQL database. There are no bash
scripts or flat-file outputs used by the framework.


────────────────────────────────────────────────────────────────────
5. DIRECTORY LAYOUT
────────────────────────────────────────────────────────────────────

    ai/         Ollama prompt builder
    config/     DB + tool binary config
    core/       pipeline, risk engine, CVE map, AI engine, validators
    modules/    one runner per CLI tool (subfinder, httpx, nmap, …)
    schemas/    Pydantic models (Asset, Service, NucleiFinding, …)
    storage/    SQLAlchemy models + persistence
    dashboard/  Streamlit UI (home + pages/)
    data/cves/  static CVE map (cve_map.json)


────────────────────────────────────────────────────────────────────
6. ENVIRONMENT VARIABLES (.env)
────────────────────────────────────────────────────────────────────

    DATABASE_URL          postgresql://user:pass@host/dbname
                          default: postgresql://localhost/dynamo_recon

    OLLAMA_URL            default: http://localhost:11434/api/generate
    OLLAMA_MODEL          default: phi3:mini
    OLLAMA_TIMEOUT        default: 900 (seconds)
                          Per-asset LLM call timeout. Raise to 1800 for
                          slower models like WhiteRabbitNeo-7B.
    OLLAMA_KEEP_ALIVE     default: 30m — how long Ollama holds the model
                          in RAM between requests

    AI_RISK_THRESHOLD     default: 20
                          Assets scoring >= this get sent to the LLM.

    SUBFINDER_BIN         optional — override binary path
    HTTPX_BIN             optional
    NMAP_BIN              optional
    GAU_BIN               optional
    KATANA_BIN            optional
    NUCLEI_BIN            optional
    FFUF_BIN              optional
    SQLMAP_BIN            optional

    WAYBACK_TIMEOUT       default: 30
    CRT_API_URL           default: https://crt.name/v1/search?apex={domain}
    DIRLIST_PATH          default: dirlist.txt


────────────────────────────────────────────────────────────────────
7. HOW IT WORKS (quick reference)
────────────────────────────────────────────────────────────────────

    - Every external tool runs as an async subprocess (asyncio).
    - Outputs are parsed into Pydantic schemas (Asset, Service, …).
    - correlate_assets() merges httpx + nmap results by IP.
    - calculate_risk() scores each asset on tech / ports / CVEs /
      nuclei severity / SQLi confirmation / exposed parameter surface.
    - Assets above AI_RISK_THRESHOLD are sent to Ollama for
      structured offensive triage (attack path, recon actions).
    - Everything persists into PostgreSQL. Change events (new asset,
      new CVE, IP flip, tech change) are logged automatically.
    - Streamlit reads the same DB — no separate data store.

    Full-mode artifacts:
      sqlmap_data/<domain>/<hash>/sqlmap.log   per-vulnerable-URL logs


      To expand the static CVE map, add entries to data/cves/cve_map.json. Live CVEs come from nuclei templates automatically. For full NVD integration, see scripts/update_cve_map.py (optional).
────────────────────────────────────────────────────────────────────
8. TROUBLESHOOTING
────────────────────────────────────────────────────────────────────

"Could not connect to the database"
    → Postgres not running, or DATABASE_URL is wrong.
    → Try:  psql "$DATABASE_URL" -c '\dt'

"Ollama unreachable" in dashboard
    → Ensure `ollama serve` is running and OLLAMA_MODEL is pulled.
    → DYNAMO degrades gracefully: scans still complete, assets still save.

"subfinder not found"
    → Ensure $GOPATH/bin is on PATH, or set SUBFINDER_BIN=/full/path.

"nuclei produced 0 findings"
    → Run: nuclei -update-templates
    → Verify severity filter — default is critical,high,medium,low.

"ffuf wordlist not found"
    → Place dirlist.txt at project root, or set DIRLIST_PATH=/abs/path.

Schema errors after upgrade
    → Run: python update_db.py  (adds missing columns safely).

Reset the DB (destroys data)
    → dropdb dynamo_recon && createdb dynamo_recon && python init_db.py


────────────────────────────────────────────────────────────────────
9. LEGAL
────────────────────────────────────────────────────────────────────

Only scan targets you own or have explicit written permission to test.
DYNAMO's full mode runs invasive tools (nuclei, ffuf, sqlmap) — do not
point it at third-party infrastructure.