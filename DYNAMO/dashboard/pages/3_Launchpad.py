import os, sys, asyncio, threading
from datetime import datetime
from dataclasses import dataclass, field

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(os.path.dirname(_HERE))
_DASH = os.path.dirname(_HERE)
for _p in (_ROOT, _DASH):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from core.datetime_utils import now as _now

def _now_utc_naive() -> datetime:
    return _now()

import streamlit as st
import pandas as pd

from _theme import apply_theme
from components.topbar import render_universal_header
from components.cards import kpi_card, section_head
from core.orchestrator import run_pipeline
from core.validators import is_valid_hostname
from queries.scans import get_scans
from queries.admin import flush_all_data, flush_scans_only, table_counts
from queries.enrichment import enriched_count, pending_ai_list
from storage.database import SessionLocal
from storage.models import ScanModel

st.set_page_config(page_title="Launchpad", page_icon=None, layout="wide", initial_sidebar_state="collapsed")
apply_theme()

# 1. Render Header
render_universal_header()

try:
    from storage.db_storage import reconcile_stale_scans
    reconcile_stale_scans(max_age_hours=24)
except Exception:
    pass

@dataclass
class ScanJob:
    domain: str
    mode: str
    enrich_ai: bool = False
    log: list = field(default_factory=list)
    started_at: datetime = field(default_factory=_now)
    finished_at: datetime | None = None
    scan_id: int | None = None
    error: str | None = None
    _thread: threading.Thread | None = None

    def start(self):
        def worker():
            try:
                res = asyncio.run(run_pipeline(
                    self.domain,
                    progress_callback=self.log.append,
                    mode=self.mode,
                    enrich_ai=self.enrich_ai,
                ))
                self.scan_id = res.get("scan_id")
            except Exception as e:
                self.error = str(e)
                self.log.append(f"[!] {e}")
            finally:
                self.finished_at = _now()

        self._thread = threading.Thread(target=worker, daemon=True)
        self._thread.start()

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()


@dataclass
class EnrichJob:
    asset_ids: list
    risk_min: int
    log: list = field(default_factory=list)
    started_at: datetime = field(default_factory=_now)
    finished_at: datetime | None = None
    summary: dict | None = None
    error: str | None = None
    _thread: threading.Thread | None = None

    def start(self):
        def worker():
            try:
                from core.enricher import enrich_assets
                self.summary = enrich_assets(
                    self.asset_ids,
                    progress_callback=self.log.append,
                    risk_min=self.risk_min,
                )
            except Exception as e:
                self.error = str(e)
                self.log.append(f"[!] {e}")
            finally:
                self.finished_at = _now()

        self._thread = threading.Thread(target=worker, daemon=True)
        self._thread.start()

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

def _elapsed_seconds(start, end) -> int:
    if not start or not end:
        return 0
    return int((end - start).total_seconds())

_ALL_PHASES = [
    "1-Passive", "2-Httpx", "2.5-Archive", "3-Nmap", "4-Katana",
    "5-FFUF", "6-Nuclei", "6.5-JS", "6.6-Passive", "6.7-Active",
    "7-SQLMap", "8-Save", "9-AI",
]

_STATUS_DOT = {
    "running":   "◐",
    "completed": "●",
    "failed":    "✕",
    "cached":    "◇",
    "pending":   "○",
    "Resumed from cache": "◇",
}

_STATUS_CLASS = {
    "running":   "running",
    "completed": "done",
    "failed":    "failed",
    "cached":    "cached",
    "Resumed from cache": "cached",
}


def _render_stepper(scan_id, mode):
    from queries.scans import scan_phase_progress

    df = scan_phase_progress(scan_id)
    seen = {}
    if not df.empty:
        for _, r in df.iterrows():
            seen[r["phase"]] = (r["status"], int(r["count"] or 0))

    applicable = list(_ALL_PHASES)
    if mode == "quick":
        applicable = [
            p for p in applicable
            if not any(k in p for k in
                       ("4-Katana", "5-FFUF", "6.5-JS", "6.6", "6.7",
                        "7-SQLMap", "6-Nuclei"))
        ]

    chips = []
    for phase in applicable:
        if phase in seen:
            status, count = seen[phase]
        else:
            status, count = ("pending", 0)
        cls = _STATUS_CLASS.get(status, "")
        dot = _STATUS_DOT.get(status, "○")
        chips.append(
            f'<div class="step {cls}">'
            f'<span class="step-dot">{dot}</span>'
            f'{phase}<br><span style="font-weight:500;font-size:9.5px;">'
            f'{status} · {count}</span></div>'
        )

    st.markdown(f'<div class="stepper">{"".join(chips)}</div>',
                unsafe_allow_html=True)


@st.fragment(run_every="3s")
def render_scan_monitor(job):
    active_scan_id = None
    active_mode = "full"
    if job and job.scan_id:
        active_scan_id = job.scan_id
        active_mode = getattr(job, "mode", "full")
    else:
        session = SessionLocal()
        try:
            running = (session.query(ScanModel)
                       .filter_by(status="running")
                       .order_by(ScanModel.started_at.desc())
                       .first())
            if running:
                active_scan_id = running.id
                active_mode = running.mode or "full"
        finally:
            session.close()

    if active_scan_id:
        st.info(f"Scan #{active_scan_id} — {active_mode} mode")
        _render_stepper(active_scan_id, active_mode)
    elif job and job.is_running:
        st.info("Initializing scan…")

    if job and job.log:
        with st.expander("Live log (last 10 lines)", expanded=False):
            st.code("\n".join(job.log[-10:]) or "…", language="bash")
    elif job and not job.is_running and job.error:
        st.error(f"Failed: {job.error}")
    elif job and not job.is_running and not job.error:
        elapsed = _elapsed_seconds(job.started_at, job.finished_at)
        st.success(f"Scan complete in {elapsed}s")


@st.fragment(run_every="3s")
def render_enrich_monitor(enrich_job):
    if enrich_job.is_running:
        st.info(f"Enriching {len(enrich_job.asset_ids)} assets...")
        st.code("\n".join(enrich_job.log[-20:]) or "…", language="bash")
    else:
        if enrich_job.error:
            st.error(enrich_job.error)
        elif enrich_job.summary:
            s = enrich_job.summary
            st.success(
                f"{s['enriched']}/{s['total']} in {s['elapsed_sec']}s "
                f"(skipped={s['skipped']}, failed={s['failed']})"
            )
        with st.expander("Full Enrichment Log"):
            st.code("\n".join(enrich_job.log) or "(empty)", language="bash")
        if st.button("Reset Enrichment Monitor", key="reset_enrich"):
            st.session_state.enrich_job = None
            st.rerun()


st.session_state.setdefault("scan_job", None)
st.session_state.setdefault("enrich_job", None)

tabs = st.tabs(["Scan", "AI Enrichment", "Settings", "History", "Admin"])

# ── SCAN ────────────────────────────────────────────────────────────────
with tabs[0]:
    col_scan, _ = st.columns([2, 1])
    with col_scan:
        section_head("Start a scan")

        job = st.session_state.scan_job
        if job and not hasattr(job, "is_running"):
            job = None
            st.session_state.scan_job = None
            
        running = bool(job and job.is_running)

        scan_domain = st.text_input(
            "Target domain",
            value=(job.domain if job else ""),
            placeholder="example.com",
            disabled=running,
            key="scan_input",
        )
        scan_mode = st.radio(
            "Mode", ["Quick", "Full"], index=0,
            disabled=running, horizontal=True,
            help="Full adds katana + ffuf + nuclei + sqlmap.",
        )
        scan_enrich = st.checkbox(
            "Run AI Enrichment inline after scan", 
            value=False, 
            disabled=running,
            help="Calls Ollama for each high-risk asset before finishing the scan."
        )
        start = st.button("Start Scan", width='stretch', disabled=running)

        if start and not running:
            d = scan_domain.strip().lower()
            if not d or not is_valid_hostname(d):
                st.error("Enter a valid domain.")
            else:
                nj = ScanJob(domain=d, mode=scan_mode.lower(), enrich_ai=scan_enrich)
                nj.start()
                st.session_state.scan_job = nj
                st.rerun()

        # Render the monitor if a job exists (running or finished)
        if job is not None:
            render_scan_monitor(job)


# ── AI ENRICHMENT ───────────────────────────────────────────────────────
with tabs[1]:
    section_head("AI Enrichment")
    risk_min = st.slider("Min risk score", 0, 100, 20, 5,
                         key="enrich_risk_min")

    try:
        pending_df = pending_ai_list(risk_min=risk_min, limit=5000)
        pending = len(pending_df)
        pending_ids = (pending_df["id"].astype(int).tolist()
                       if not pending_df.empty else [])
        enriched = enriched_count()
    except Exception as e:
        st.error(f"Could not read counts: {e}")
        pending_df = pd.DataFrame()
        pending = enriched = 0
        pending_ids = []

    c1, c2 = st.columns(2)
    with c1:
        kpi_card("Pending", pending,
                 accent="medium" if pending > 0 else None)
    with c2:
        kpi_card("Enriched", enriched, accent=None)

    enrich_job = st.session_state.enrich_job
    
    if enrich_job and not hasattr(enrich_job, "is_running"):
        enrich_job = None
        st.session_state.enrich_job = None
        
    enrich_running = bool(enrich_job and enrich_job.is_running)

    if "enrich_result" in st.session_state:
        r = st.session_state.pop("enrich_result")
        (st.success if r["ok"] else st.error)(r["msg"])

    if enrich_job is not None:
        render_enrich_monitor(enrich_job)
    else:
        confirm = st.checkbox(
            "I understand this will call Ollama for each asset",
            key="confirm_enrich",
        )
        btn = st.button(
            "Enrich pending",
            disabled=(not confirm) or pending == 0,
            width='stretch',
            key="btn_enrich",
        )
        if btn:
            if not pending_ids:
                st.session_state.enrich_result = {
                    "ok": True, "msg": "Nothing pending."
                }
                st.rerun()
            else:
                st.session_state.enrich_job = EnrichJob(
                    asset_ids=pending_ids, risk_min=risk_min)
                st.session_state.enrich_job.start()
                st.rerun()

    with st.expander("View Pending Assets"):
        if pending_df.empty:
            st.markdown(
                '<p class="dyn-caption">Nothing pending.</p>',
                unsafe_allow_html=True,
            )
        else:
            st.dataframe(pending_df.head(100), width='stretch',
                         hide_index=True)

# ── SETTINGS ────────────────────────────────────────────────────────────
with tabs[2]:
    from config.runtime import (
        list_ollama_models, get_model_for_task, set_model_for_task,
    )

    section_head("AI Model Settings")
    st.markdown(
        '<p class="dyn-caption">Choose which installed Ollama models to use for '
        'triage (fast) and deep analysis (thorough). Applies to all future scans '
        'and enrichments.</p>',
        unsafe_allow_html=True,
    )

    installed = list_ollama_models()
    if not installed:
        st.warning(
            "Could not reach Ollama at http://localhost:11434. "
            "Run `ollama serve` and refresh."
        )
        current_triage = get_model_for_task("triage")
        current_deep = get_model_for_task("deep")
        st.info(
            f"Current settings: triage=`{current_triage}`, deep=`{current_deep}`"
        )
    else:
        current_triage = get_model_for_task("triage")
        current_deep = get_model_for_task("deep")

        def _index_of(options, value):
            try:
                return options.index(value)
            except ValueError:
                return 0

        c1, c2 = st.columns(2)
        with c1:
            new_triage = st.selectbox(
                "Triage model (fast path)",
                installed,
                index=_index_of(installed, current_triage),
                key="triage_model_pick",
            )
        with c2:
            new_deep = st.selectbox(
                "Deep model (analysis)",
                installed,
                index=_index_of(installed, current_deep),
                key="deep_model_pick",
            )

        if st.button("Save model settings", width='stretch'):
            try:
                set_model_for_task("triage", new_triage)
                set_model_for_task("deep", new_deep)
                st.success(f"Saved: triage={new_triage}, deep={new_deep}")
            except Exception as e:
                st.error(f"Save failed: {e}")

        with st.expander("Show all installed models"):
            st.write(installed)

# ── HISTORY ─────────────────────────────────────────────────────────────
with tabs[3]:
    try:
        scans = get_scans()
        if scans.empty:
            st.info("No scans yet.")
        else:
            cols_wanted = [c for c in [
                "id", "target", "mode", "status", "started_at", "completed_at",
                "subfinder_count", "crt_count", "gau_count", "wayback_count",
                "httpx_count", "nmap_ip_count", "nmap_service_count",
                "katana_count", "ffuf_count", "nuclei_count", "sqli_count",
                "saved_asset_count", "active_assets",
            ] if c in scans.columns]
            st.dataframe(scans[cols_wanted], width='stretch',
                         hide_index=True)
    except Exception as e:
        st.error(f"Could not load scans: {e}")

# ── ADMIN ───────────────────────────────────────────────────────────────
with tabs[4]:
    st.warning("Destructive operations. These cannot be undone.")

    with st.expander("Connection check"):
        if st.button("Ping DB", key="admin_ping"):
            try:
                from queries.admin import ping
                st.success(f"Connected: {ping()}")
            except Exception as e:
                st.error(f"Ping failed: {e}")

    if "admin_result" in st.session_state:
        r = st.session_state.pop("admin_result")
        (st.success if r["ok"] else st.error)(r["msg"])

    section_head("Current table sizes")
    try:
        counts = table_counts()
        size_df = pd.DataFrame(
            [{"Table": k, "Rows": v} for k, v in counts.items()])
        st.dataframe(size_df, width='stretch', hide_index=True)
    except Exception as e:
        st.error(f"Could not read counts: {e}")

    section_head("Surgical Deletion")
    st.markdown(
        '<p class="dyn-caption">Delete a specific scan or a specific target domain '
        '(including all of its assets and findings) without touching anything else.</p>',
        unsafe_allow_html=True,
    )
    
    del_mode = st.radio("What do you want to delete?", ["Single Scan", "Single Target (Domain)"], horizontal=True)
    
    if del_mode == "Single Scan":
        from queries.scans import get_scans
        try:
            scans_df = get_scans()
            if not scans_df.empty:
                scan_opts = {f"Scan #{r['id']} — {r['target']} ({r['started_at']})": int(r['id']) for _, r in scans_df.iterrows()}
                selected_scan_label = st.selectbox("Select Scan to Delete", list(scan_opts.keys()))
                selected_scan_id = scan_opts[selected_scan_label]
                
                confirm_scan_del = st.checkbox(f"I confirm I want to delete Scan #{selected_scan_id} and its logs", key="confirm_scan_del")
                if st.button("Delete Scan", disabled=not confirm_scan_del, width='stretch', type="primary"):
                    try:
                        from queries.admin import delete_scan_by_id
                        delete_scan_by_id(selected_scan_id)
                        st.session_state.admin_result = {"ok": True, "msg": f"Scan #{selected_scan_id} deleted successfully."}
                    except Exception as e:
                        st.session_state.admin_result = {"ok": False, "msg": str(e)}
                    st.rerun()
            else:
                st.info("No scans available to delete.")
        except Exception as e:
            st.error(f"Could not load scans: {e}")

    else:
        from queries.domains import get_domains
        try:
            doms_df = get_domains()
            if not doms_df.empty:
                dom_opts = {f"{r['apex']} ({r['total_assets']} assets)": int(r['domain_id']) for _, r in doms_df.iterrows()}
                selected_dom_label = st.selectbox("Select Target to Delete", list(dom_opts.keys()))
                selected_dom_id = dom_opts[selected_dom_label]
                
                st.warning(f" This will permanently delete {selected_dom_label} and all of its associated IPs, services, CVEs, and vulnerability data.")
                confirm_dom_del = st.checkbox(f"I confirm I want to delete {selected_dom_label}", key="confirm_dom_del")
                if st.button("Delete Target & Assets", disabled=not confirm_dom_del, width='stretch', type="primary"):
                    try:
                        from queries.admin import delete_target_by_id
                        delete_target_by_id(selected_dom_id)
                        st.session_state.admin_result = {"ok": True, "msg": f"Target {selected_dom_label} and all related assets deleted successfully."}
                    except Exception as e:
                        st.session_state.admin_result = {"ok": False, "msg": str(e)}
                    st.rerun()
            else:
                st.info("No domains available to delete.")
        except Exception as e:
            st.error(f"Could not load domains: {e}")

    st.markdown("---")

    section_head("Delete scan history")
    st.markdown(
        '<p class="dyn-caption">Wipes scans and dependent rows. '
        'Keeps assets and domains intact.</p>',
        unsafe_allow_html=True,
    )
    confirm_scans = st.checkbox(
        "I understand this deletes all scan history",
        key="confirm_flush_scans",
    )
    if st.button("Flush scans", disabled=not confirm_scans,
                 width='stretch', key="btn_flush_scans"):
        try:
            flush_scans_only()
            st.session_state.admin_result = {
                "ok": True, "msg": "Scans flushed."
            }
        except Exception as e:
            st.session_state.admin_result = {"ok": False, "msg": str(e)}
        st.rerun()

    section_head("Delete EVERYTHING")
    st.markdown(
        '<p class="dyn-caption">Truncates every recon table and resets IDs.</p>',
        unsafe_allow_html=True,
    )
    typed = st.text_input("Type FLUSH to confirm", key="flush_confirm")
    if st.button("Flush all data",
                 disabled=(typed.strip().upper() != "FLUSH"),
                 width='stretch', key="btn_flush_all"):
        try:
            flush_all_data()
            st.session_state.admin_result = {
                "ok": True, "msg": "Database wiped clean."
            }
        except Exception as e:
            st.session_state.admin_result = {"ok": False, "msg": str(e)}
        st.rerun()