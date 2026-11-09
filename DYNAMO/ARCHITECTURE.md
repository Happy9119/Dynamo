# DYNAMO Architecture Map

## Data flow (one scan)
main.py → run_pipeline(domain, mode)
  │
  ├─ Phase 1: subfinder ‖ crt ‖ gau ‖ wayback → List[str] (subdomains)
  ├─ Phase 2: run_httpx(subs) → List[dict] → normalize_httpx(d) → Asset
  ├─ Phase 3: run_nmap(ip) × N → parse_nmap_xml() → normalize_nmap() → Asset[]
  ├─ (full) Phase 4: run_katana(hosts) → List[str]
  ├─ (full) Phase 5: run_ffuf(host) × M → List[str]
  ├─ (full) Phase 6: run_nuclei(urls) + run_nuclei(ips) → List[dict]
  ├─ (full) Phase 6.5–7: vapt/* + sqlmap
  └─ Phase 8: correlate_assets(httpx_assets, nmap_assets) → Asset[]
              _attach_url_intel(), _attach_vapt_findings()
              calculate_risk(asset) → (int, str)
              save_asset_to_db(asset, scan_id, mode)

## Key types
schemas/asset.py:
  - Asset          (in-memory, all fields)
  - Service, NucleiFinding, SQLiFinding, VulnFinding
  - AIIntelligence (Ollama JSON-schema target)

storage/models.py:
  - AssetModel ↔ Asset           via load_asset_for_ai()
  - ScanModel, AssetObservationModel, ChangeEventModel, ...
  - DomainModel ↔ DomainAssetModel (M:N with AssetModel)

## Extension points (where to add features)
New recon tool:       modules/<tool>_runner.py + phase file + config/tools.py
New risk rule:        core/risk_engine.py — add to RISKY_* dicts or CVE_SEVERITY_POINTS
New VAPT check:       vapt/<check>.py + wire in vapt/runner.py::run_passive_checks
New dashboard page:   dashboard/pages/N_Name.py
New AI field:         schemas/asset.py::AIIntelligence + ai/ai_prompts.py schema block
New DB column:        storage/models.py + run update_db.py

## Files by "change blast radius"
🟢 Isolated (safe to edit alone):
  core/risk_engine.py, core/cve_lookup.py, core/validators.py,
  modules/*_runner.py, vapt/*.py, ai/ai_prompts.py, dashboard/queries/*.py
  dashboard/pages/*.py

🟡 Cross-cutting (check callers first):
  schemas/asset.py (everything), config/tools.py (every module),
  storage/db_storage.py (all save/load), core/cve_lookup.py (matching logic)

🔴 Dangerous (never edit casually):
  core/orchestrator.py::run_pipeline (control flow + resumability)
  core/ai_engine.py::_get_cache_key (cache invalidation)
  storage/db_storage.py::save_asset_to_db (change-event logic)
  vapt/js_analysis.py scope checks (pentest safety)