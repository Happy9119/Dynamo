import os, sys
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(os.path.dirname(_HERE))
_DASH = os.path.dirname(_HERE)
for _p in (_ROOT, _DASH):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import streamlit as st
import pandas as pd

from _theme import apply_theme
from components.topbar import render_universal_header
from components.cards import kpi_card, finding_card, section_head, _esc
from components.tables import download_df
from components.empty_state import empty_state, error_state
from queries.findings import list_all_findings, findings_summary
from queries.assets import findings_grouped_by_asset

st.set_page_config(page_title="Exposure", page_icon=None, layout="wide", initial_sidebar_state="collapsed")
apply_theme()

# 1. Render Header
render_universal_header()

# FIX #1: ffuf is now a first-class source in the UI
st.session_state.setdefault("exp_sev", ["critical", "high", "medium"])
st.session_state.setdefault("exp_src", ["vapt", "sqli", "nuclei", "cve", "ffuf"])
st.session_state.setdefault("exp_text", "")
st.session_state.setdefault("exp_group", True)

c1, c2, c3 = st.columns([2, 2, 3])
with c1:
    sev_filter = st.multiselect(
        "Severity",
        ["critical", "high", "medium", "low", "info"],
        default=st.session_state.exp_sev,
        key="exp_sev_widget",
    )
    st.session_state.exp_sev = sev_filter
with c2:
    source_filter = st.multiselect(
        "Source",
        ["vapt", "sqli", "nuclei", "cve", "ffuf"],
        default=st.session_state.exp_src,
        key="exp_src_widget",
    )
    st.session_state.exp_src = source_filter
with c3:
    text_filter = st.text_input(
        "Search title, host, or URL",
        value=st.session_state.exp_text,
        key="exp_text_widget",
        placeholder="e.g. ssrf, admin, login",
    )
    st.session_state.exp_text = text_filter

toggle_cols = st.columns([1, 1, 6])
with toggle_cols[0]:
    group = st.checkbox("Group by host", value=st.session_state.exp_group,
                        key="exp_group_widget")
    st.session_state.exp_group = group
with toggle_cols[1]:
    show_reviewed = st.checkbox("Show reviewed", value=False,
                                key="exp_show_reviewed")

try:
    summ = findings_summary()
    kcols = st.columns(5)
    for col, (label, key, accent) in zip(kcols, [
        ("Critical", "critical", "critical"),
        ("High",     "high",     "high"),
        ("Medium",   "medium",   "medium"),
        ("Low",      "low",      "low"),
        ("Info",     "info",     "info"),
    ]):
        with col:
            v = summ.get(key, 0)
            kpi_card(label, v, accent=accent if v > 0 else None)
except Exception as e:
    error_state("Could not load summary", str(e), retry_key="exposure_kpi")
    st.stop()

section_head("Findings")

try:
    df = findings_grouped_by_asset(
        severities=st.session_state.exp_sev or None,
        sources=st.session_state.exp_src or None,
        text_filter=st.session_state.exp_text or "",
        limit=5000,
    )
except Exception as e:
    error_state("Could not load findings", str(e), retry_key="exposure_load")
    st.stop()

if df.empty:
    empty_state(
        "No findings match the current filters.",
        "Try widening the severity or source filter, or clearing the search.",
        icon="◇",
    )
    st.stop()

import hashlib as _hashlib

reviewed_set = st.session_state.get("reviewed_findings", set())

def _finding_id(row):
    raw = "|".join(str(row.get(k, "") or "") for k in (
        "source", "host", "title", "url", "evidence",
    ))
    return _hashlib.sha256(raw.encode()).hexdigest()[:20]

df["_key"] = df.apply(_finding_id, axis=1)
if not show_reviewed:
    df = df[~df["_key"].isin(reviewed_set)]

st.markdown(
    f'<p class="dyn-caption">Showing {len(df)} findings.</p>',
    unsafe_allow_html=True,
)

if st.session_state.exp_group:
    df = df.sort_values(
        by=["host", "severity"],
        key=lambda c: c.map({"critical": 0, "high": 1, "medium": 2,
                              "low": 3, "info": 4}) if c.name == "severity" else c,
    )
    last_host = None
    for i, (_, f) in enumerate(df.iterrows()):
        if f["host"] != last_host:
            st.markdown(
                f'<div class="section-head" style="margin-top:14px;">'
                f'<span class="sec-title">{_esc(f["host"])}</span>'
                f'</div>',
                unsafe_allow_html=True,
            )
            last_host = f["host"]
        finding_card(
            severity=f["severity"],
            host=f["host"],
            title=f["title"],
            source=f["source"],
            url=f.get("url") or None,
            evidence=f.get("evidence") or None,
            idx=i,
            finding_key=f["_key"],
        )
else:
    for i, (_, f) in enumerate(df.iterrows()):
        finding_card(
            severity=f["severity"],
            host=f["host"],
            title=f["title"],
            source=f["source"],
            url=f.get("url") or None,
            evidence=f.get("evidence") or None,
            idx=i,
            finding_key=f["_key"],
        )

st.markdown("")
download_df(df.drop(columns=["_key"]), "Download findings CSV", "findings.csv")