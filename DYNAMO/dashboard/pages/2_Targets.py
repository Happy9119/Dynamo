import os, sys, json
from pathlib import Path

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(os.path.dirname(_HERE))
_DASH = os.path.dirname(_HERE)
for _p in (_ROOT, _DASH):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import streamlit as st
import pandas as pd
import hashlib as _hashlib

from _theme import apply_theme
from components.topbar import render_universal_header
from components.cards import (
    kpi_card, finding_card, section_head,
)
from components.tables import download_df
from components.empty_state import empty_state
from queries.assets import list_assets, get_asset_detail
from queries.services import (
    list_ips, list_services, list_cves, service_fingerprints,
)
from queries.timeline import (
    get_change_events, get_event_types,
    get_scans_for_domain, get_scan_observations, diff_observations,
)
from queries.findings import list_all_findings, findings_summary
from queries.nmap_view import nmap_files_df, read_nmap_file
from queries.domains import get_domains
from queries.reporting import generate_domain_report
from schemas.asset import AIIntelligence

st.set_page_config(page_title="Targets", page_icon=None, layout="wide", initial_sidebar_state="collapsed")
apply_theme()

# 1. Render Header
render_universal_header()

dom_df = get_domains()
if dom_df.empty:
    st.info("No domains yet. Run a scan from the Launchpad first.")
    st.stop()

_options = {
    f"{r['apex']}  ({r['active_assets']} active)": int(r["domain_id"])
    for _, r in dom_df.iterrows()
}

_current = st.session_state.get("filter_domain_id")
_default_idx = 0
if _current is not None and _current in _options.values():
    _default_idx = list(_options.values()).index(_current)

_selected = st.selectbox(
    "Select a target domain",
    list(_options.keys()),
    index=_default_idx,
    key="targets_inline_domain",
    label_visibility="collapsed"
)
did = _options[_selected]
st.session_state.filter_domain_id = did

apex = dom_df[dom_df["domain_id"] == did].iloc[0]["apex"]

try:
    summ = findings_summary(domain_id=did)
    assets = list_assets(
        domain_id=did,
        limit=10000,
    )
    cols = st.columns(5)
    with cols[0]:
        kpi_card("Hosts", len(assets), accent=None)
    with cols[1]:
        kpi_card("Critical", summ["critical"],
                 accent="critical" if summ["critical"] > 0 else None)
    with cols[2]:
        kpi_card("High", summ["high"],
                 accent="high" if summ["high"] > 0 else None)
    with cols[3]:
        kpi_card("Medium", summ["medium"],
                 accent="medium" if summ["medium"] > 0 else None)
    with cols[4]:
        kpi_card("Total Findings", summ["total"], accent=None)
except Exception as e:
    st.error(f"Could not load KPIs: {e}")

tabs = st.tabs(["Findings", "Assets", "Timeline", "Report"])

# ── FINDINGS ────────────────────────────────────────────────────────────
with tabs[0]:
    c1, c2 = st.columns([3, 2])
    with c1:
        sev_filter = st.multiselect(
            "Severity",
            ["critical", "high", "medium", "low", "info"],
            default=["critical", "high", "medium", "low"],
        )
    with c2:
        # FIX #1: ffuf is now selectable here too
        source_filter = st.multiselect(
            "Source",
            ["vapt", "sqli", "nuclei", "cve", "ffuf"],
            default=["vapt", "sqli", "nuclei", "cve", "ffuf"],
        )

    try:
        df = list_all_findings(
            domain_id=did,
            severities=sev_filter or None,
            sources=source_filter or None,
            limit=2000,
        )
    except Exception as e:
        st.error(f"Could not load findings: {e}")
        df = pd.DataFrame()

    if df.empty:
        st.success("No findings match the current filters.")
    else:
        # Generate unique keys for review state tracking
        def _finding_id(row):
            raw = "|".join(str(row.get(k, "") or "") for k in (
                "source", "host", "title", "url", "evidence",
            ))
            return _hashlib.sha256(raw.encode()).hexdigest()[:20]
        
        df["_key"] = df.apply(_finding_id, axis=1)

        st.markdown(
            f'<p class="dyn-caption">Showing {len(df)} findings.</p>',
            unsafe_allow_html=True,
        )
        for i, (_, f) in enumerate(df.iterrows()):
            finding_card(
                severity=f["severity"],
                host=f["host"],
                title=f["title"],
                source=f["source"],
                url=f.get("url") or None,
                evidence=f.get("evidence") or None,
                idx=i,
                finding_key=f["_key"], # Pass the generated key
            )
        st.markdown("")
        download_df(df.drop(columns=["_key"]), "Download findings CSV", f"{apex}_findings.csv")

# ── ASSETS ──────────────────────────────────────────────────────────────
with tabs[1]:
    sub = st.tabs(["Hosts", "IPs", "Services", "Fingerprints", "Nmap"])

    with sub[0]:
        host_search = st.text_input("Filter hosts", placeholder="Search by hostname or IP...", label_visibility="collapsed")
        
        try:
            hosts = list_assets(
                domain_id=did,
                search=host_search,
                limit=5000,
            )
        except Exception as e:
            st.error(f"Could not load hosts: {e}")
            hosts = pd.DataFrame()

        if hosts.empty:
            empty_state(
                "No hosts match",
                "Try a different search term or run a scan.",
                icon="◈",
                cta_label="Open Launchpad →",
                cta_path="pages/3_Launchpad.py",
            )
        else:
            disp = hosts.rename(columns={
                "host": "Host", "ip": "IP", "title": "Title",
                "technologies": "Technologies", "risk_score": "Risk",
                "is_active": "Active", "last_seen": "Last seen",
            })[["Host", "IP", "Title", "Technologies", "Risk",
                "Active", "Last seen"]]
            st.dataframe(
                disp,
                width="stretch",
                hide_index=True,
                column_config={
                    "Risk": st.column_config.ProgressColumn(
                        "Risk",
                        help="Risk score (0–100)",
                        min_value=0, max_value=100, format="%d",
                    ),
                    "Active": st.column_config.CheckboxColumn("Active"),
                },
            )
            download_df(disp, "Download hosts CSV", f"{apex}_hosts.csv")

            section_head("Host drill-in")
            opts = {f"{r['host']}  ({r['ip'] or 'no IP'})": int(r["id"])
                    for _, r in hosts.iterrows()}
            picked = st.selectbox("Pick a host", list(opts))
            detail = get_asset_detail(opts[picked])
            if detail:
                c1, c2 = st.columns([2, 1])
                with c1:
                    st.markdown(f"**{detail['asset_value']}**")
                    st.write(f"IP: `{detail['ip_address'] or '—'}`")
                    st.write(f"URL: {detail['url'] or '—'}")
                    st.write(f"Title: {detail['title'] or '—'}")
                    st.write(f"Technologies: {detail['technologies'] or '—'}")
                with c2:
                    st.metric("Risk", detail["risk_score"])
                    st.write(f"Active: {detail['is_active']}")
                    st.write(f"Last seen: {detail['last_seen']}")

                import plotly.graph_objects as go
                score = int(detail.get("risk_score") or 0)
                gauge = go.Figure(go.Indicator(
                    mode="gauge+number",
                    value=score,
                    gauge={
                        "axis": {"range": [0, 100]},
                        "bar": {"color": "#6366F1"},
                        "steps": [
                            {"range": [0, 20],  "color": "#FEF9C3"},
                            {"range": [20, 50], "color": "#FFEDD5"},
                            {"range": [50, 80], "color": "#FEE2E2"},
                            {"range": [80, 100],"color": "#FECACA"},
                        ],
                    },
                ))
                gauge.update_layout(height=180, margin=dict(t=10, b=10, l=10, r=10))
                st.plotly_chart(gauge, width="stretch", theme="streamlit")

                if detail.get("ai_analysis_json"):
                    section_head("AI Triage")
                    try:
                        ai_obj = AIIntelligence(**json.loads(
                            detail["ai_analysis_json"]))
                        st.metric(
                            "Exploitability",
                            f"{ai_obj.exploitability_score}/100",
                            ai_obj.exploitability_tier,
                        )
                        st.info(ai_obj.attack_vector_summary)
                        for step in ai_obj.attack_path:
                            st.markdown(
                                f"**Step {step.step_number}: {step.title}** "
                                f"— `{step.target_component}`")
                            st.caption(step.description)
                    except Exception:
                        st.json(detail["ai_analysis_json"])

    with sub[1]:
        ips = list_ips(domain_id=did)
        if ips.empty:
            st.info("No IP data.")
        else:
            st.dataframe(ips, width='stretch', hide_index=True)
            download_df(ips, "Download IPs CSV", f"{apex}_ips.csv")

    with sub[2]:
        svcs = list_services(domain_id=did) 
        if svcs.empty:
            st.info("No service data.")
        else:
            st.dataframe(svcs, width='stretch', hide_index=True)
            download_df(svcs, "Download services CSV", f"{apex}_services.csv")

    with sub[3]:
        fps = service_fingerprints(domain_id=did)
        if fps.empty:
            st.info("No fingerprints recorded.")
        else:
            st.dataframe(fps, width='stretch', hide_index=True)
            download_df(fps, "Download fingerprints CSV",
                        f"{apex}_fingerprints.csv")

    with sub[4]:
        files_df = nmap_files_df(apex)
        if files_df.empty:
            st.info("No nmap output for this domain.")
        else:
            st.dataframe(files_df, width='stretch', hide_index=True)

            view_mode = st.radio(
                "View",
                ["Latest per IP", "Specific scan"],
                horizontal=True,
                key="nmap_view_mode",
            )

            if view_mode == "Latest per IP":
                latest = (
                    files_df.dropna(subset=["scan_id"])
                    .sort_values("scan_id", ascending=False)
                    .drop_duplicates(subset=["ip"], keep="first")
                )
                if latest.empty:
                    latest = files_df.drop_duplicates(subset=["ip"], keep="first")
                picked_ip = st.selectbox("Select IP", latest["ip"].tolist())
                picked_row = latest[latest["ip"] == picked_ip].iloc[0]
                path = Path(picked_row["path"])
            else:
                labeled = [
                    f"{r['ip']}  —  scan {r['scan_id'] if r['scan_id'] else 'legacy'}"
                    for _, r in files_df.iterrows()
                ]
                picked_label = st.selectbox("Select capture", labeled)
                idx = labeled.index(picked_label)
                picked_row = files_df.iloc[idx]
                path = Path(picked_row["path"])

            content = read_nmap_file(path)
            st.code(content or "(empty)", language="text")
            st.download_button(
                "Download nmap output",
                data=(content or "").encode(),
                file_name=path.name,
            )

# ── TIMELINE ────────────────────────────────────────────────────────────
with tabs[2]:
    tl = st.tabs(["Events", "Scan diff"])

    with tl[0]:
        try:
            types = get_event_types()
            if "tl_events_filter" not in st.session_state:
                st.session_state.tl_events_filter = types
            chosen = st.multiselect("Filter event type", types,
                                    key="tl_events_filter")
            chosen = chosen or None
            events = get_change_events(domain_id=did,
                                       event_types=chosen, limit=1000)
            if events.empty:
                st.info("No events for this scope.")
            else:
                st.dataframe(events, width='stretch', hide_index=True)
                download_df(events, "Download events CSV",
                            f"{apex}_events.csv")
        except Exception as e:
            st.error(f"Timeline error: {e}")

    with tl[1]:
        scans = get_scans_for_domain(domain_id=did)
        if len(scans) < 2:
            st.warning("Need at least two scans to diff.")
        else:
            def _lbl(r):
                ts = (r["started_at"].strftime("%d-%m-%Y %H:%M:%S")
                      if hasattr(r["started_at"], "strftime")
                      else str(r["started_at"]))
                return f"#{int(r['id'])}  —  {ts}  ({r['status']})"
            labels = [_lbl(r) for _, r in scans.iterrows()]
            id_of = {lbl: int(r["id"])
                     for lbl, (_, r) in zip(labels, scans.iterrows())}
            c1, c2 = st.columns(2)
            with c1:
                a_lbl = st.selectbox("Baseline", labels,
                                     index=len(labels) - 1)
            with c2:
                b_lbl = st.selectbox("Comparison", labels, index=0)
            sa, sb = id_of[a_lbl], id_of[b_lbl]
            if sa == sb:
                st.warning("Pick two different scans.")
            else:
                try:
                    obs_a = get_scan_observations(sa)
                    obs_b = get_scan_observations(sb)
                    diff = diff_observations(obs_a, obs_b)
                    section_head(f"#{sa} → #{sb}")
                    cols = st.columns(6)
                    for col, (lbl, val) in zip(cols, [
                        ("Hosts A", len(obs_a)),
                        ("Hosts B", len(obs_b)),
                        ("Added", len(diff["added_hosts"])),
                        ("Removed", len(diff["removed_hosts"])),
                        ("IP flips", len(diff["ip_changes"])),
                        ("New CVEs", len(diff["added_cves"])),
                    ]):
                        with col:
                            kpi_card(lbl, val, accent=None)

                    for title, rows_, cols_ in [
                        ("New VAPT Findings", diff["added_vapt"],
                         ["Host", "Type", "URL", "Severity"]),
                        ("Fixed/Removed VAPT Findings", diff["removed_vapt"],
                         ["Host", "Type", "URL", "Severity"]),
                        ("New Nuclei Findings", diff["added_nuclei"],
                         ["Host", "Template", "URL", "Severity"]),
                        ("Fixed/Removed Nuclei Findings", diff["removed_nuclei"],
                         ["Host", "Template", "URL", "Severity"]),
                        ("New SQLi", diff["added_sqli"],
                         ["Host", "URL", "Technique"]),
                        ("Fixed/Removed SQLi", diff["removed_sqli"],
                         ["Host", "URL", "Technique"]),
                        ("Added hosts", diff["added_hosts"],
                         ["Host", "IP"]),
                        ("Removed hosts", diff["removed_hosts"],
                         ["Host", "IP"]),
                        ("IP changes", diff["ip_changes"],
                         ["Host", "Old IP", "New IP"]),
                        ("Added services", diff["added_services"],
                         ["Host", "Port/Proto", "Service"]),
                        ("Removed services", diff["removed_services"],
                         ["Host", "Port/Proto", "Service"]),
                        ("Service fingerprint changes",
                         diff["fingerprint_changes"],
                         ["Host", "Service", "Old", "New"]),
                        ("New CVEs", diff["added_cves"],
                         ["Host", "CVE", "Severity"]),
                        ("Resolved CVEs", diff["removed_cves"],
                         ["Host", "CVE", "Severity"]),
                        ("AI re-assessment", diff["ai_changes"],
                         ["Host", "Change", "Detail"]),
                    ]:
                        section_head(title)
                        if rows_:
                            st.dataframe(
                                pd.DataFrame(rows_, columns=cols_),
                                width='stretch', hide_index=True)
                        else:
                            st.markdown(
                                '<p class="dyn-caption">None.</p>',
                                unsafe_allow_html=True,
                            )

                except Exception as e:
                    st.error(f"Diff failed: {e}")

# ── REPORT ──────────────────────────────────────────────────────────────
with tabs[3]:
    section_head(f"PDF Report — {apex}")
    st.markdown(
        '<p class="dyn-caption">Bundles every finding, asset, and event '
        'into a single PDF.</p>',
        unsafe_allow_html=True,
    )
    report_type = st.radio("Report Type", ["Full Technical", "Executive Summary"], horizontal=True)
    if st.button("Generate PDF", width='stretch'):
        with st.spinner("Building report…"):
            try:
                rtype = "exec" if report_type == "Executive Summary" else "full"
                pdf_bytes, filename = generate_domain_report(did, report_type=rtype)
                st.session_state["report_bytes"] = pdf_bytes
                st.session_state["report_filename"] = filename
                st.session_state["report_domain"] = apex
                st.success(f"Ready — {len(pdf_bytes) / 1024:.0f} KB")
            except Exception as e:
                st.error(f"Report failed: {e}")

    if (st.session_state.get("report_domain") == apex
            and st.session_state.get("report_bytes")):
        st.download_button(
            "Download PDF",
            data=st.session_state["report_bytes"],
            file_name=st.session_state["report_filename"],
            mime="application/pdf",
            width='stretch',
        )