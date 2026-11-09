import os, sys
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for _p in (_ROOT, _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import streamlit as st
import pandas as pd

from _theme import apply_theme
from components.topbar import render_universal_header
from components.cards import (
    section_head, severity_strip,
    kpi_card, finding_card, domains_table,
)
from components.empty_state import empty_state
from components.tables import download_df

from queries.domains import get_domains
from queries.findings import list_all_findings, findings_summary_all
from queries.enrichment import pending_ai_count

st.set_page_config(page_title="Dashboard", page_icon=None, layout="wide", initial_sidebar_state="collapsed")
apply_theme()

# 1. Render Header
render_universal_header()

try:
    from storage.db_storage import reconcile_stale_scans
    reconcile_stale_scans(max_age_hours=6)
except Exception:
    pass

try:
    dom_df = get_domains()
    domains_count = len(dom_df)
    pending_ai = pending_ai_count()
    
    # Fetch the summary for the top KPI strip and the domain table in one query
    df_summary = findings_summary_all()
    
    if df_summary.empty:
        overall_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}
        summary_map = {}
    else:
        overall_summary = {
            "critical": int(df_summary["critical"].sum()),
            "high": int(df_summary["high"].sum()),
            "medium": int(df_summary["medium"].sum()),
            "low": int(df_summary["low"].sum()),
            "info": int(df_summary["info"].sum()),
            "total": int(df_summary["total"].sum()),
        }
        summary_map = df_summary.set_index("domain").to_dict(orient="index")
        
except Exception as e:
    from components.empty_state import error_state
    error_state("Could not load data", str(e), retry_key="dashboard_retry")
    st.stop()

c1, c2, c3, c4 = st.columns(4)
with c1:
    kpi_card("Domains", domains_count, foot="targets tracked", accent=None)
with c2:
    kpi_card("Total Findings", overall_summary["total"],
             foot="across all severities", accent=None)
with c3:
    kpi_card("Critical", overall_summary["critical"],
             foot="immediate action" if overall_summary["critical"] else "none detected",
             accent="critical" if overall_summary["critical"] else None)
with c4:
    kpi_card("Pending AI", pending_ai,
             foot="awaiting enrichment" if pending_ai else "all enriched",
             accent="info" if pending_ai else None)

severity_strip(overall_summary)

section_head(
    "Targets",
    meta=f"{domains_count} domain{'s' if domains_count != 1 else ''}",
)

if dom_df.empty:
    empty_state(
        "No targets yet",
        "Run your first scan to populate this dashboard.",
        icon="◈",
        cta_label="Open Launchpad →",
        cta_path="pages/3_Launchpad.py",
    )
else:
    filter_text = st.text_input("Filter targets", placeholder="Filter by domain name...", label_visibility="collapsed")
    
    rows = []
    for _, r in dom_df.iterrows():
        domain_name = r["apex"]
        s = summary_map.get(domain_name, {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0})
        
        risk_score = (s["critical"] * 4) + (s["high"] * 3) + (s["medium"] * 2) + (s["low"] * 1)
        
        rows.append({
            "domain":   domain_name,
            "assets":   int(r["active_assets"]),
            "findings": s["total"],
            "risk_score": risk_score,
            "critical": s["critical"],
            "high":     s["high"],
            "medium":   s["medium"],
            "low":      s["low"],
        })
    
    if filter_text:
        rows = [r for r in rows if filter_text.lower() in r["domain"].lower()]
        
    rows.sort(key=lambda x: -x["risk_score"])
    domains_table(rows)

    dl_df = pd.DataFrame(rows).rename(columns={
        "domain": "Domain", "assets": "Assets", "findings": "Findings",
        "risk_score": "Risk Score",
        "critical": "Critical", "high": "High",
        "medium": "Medium", "low": "Low",
    })
    st.markdown("")
    download_df(dl_df, "Download CSV", "domains_summary.csv")

try:
    feed = list_all_findings(
        severities=["critical", "high"],
        limit=20,
    )
    section_head(
        "Recent Critical & High",
        meta=f"{len(feed)} shown" if not feed.empty else None,
    )
    if feed.empty:
        st.success("No critical or high findings across the scanned targets.")
    else:
        import hashlib as _hashlib
        for i, (_, f) in enumerate(feed.iterrows()):
            _raw = "|".join(str(f.get(k, "") or "") for k in (
                "source", "host", "title", "url", "evidence",
            ))
            _key = _hashlib.sha256(_raw.encode()).hexdigest()[:20]
            finding_card(
                severity=f["severity"],
                host=f["host"],
                title=f["title"],
                source=f["source"],
                url=f.get("url") or None,
                evidence=f.get("evidence") or None,
                idx=i,
                finding_key=_key,
            )
except Exception as e:
    st.warning(f"Could not load findings feed: {e}")