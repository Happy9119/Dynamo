import streamlit as st
from sqlalchemy import text
from storage.database import engine


NAV_ITEMS = [
    ("Dashboard", "Dashboard.py"),
    ("Targets", "pages/2_Targets.py"),
    ("Exposure", "pages/1_Exposure.py"),
    ("Launchpad", "pages/3_Launchpad.py"),
    ("Scan Output", "pages/4_Scans.py"),
]


def _run_search(q):
    q_like = f"%{q}%"
    with engine.connect() as conn:
        hosts = conn.execute(text("""
            SELECT DISTINCT a.asset_value AS host, d.id AS domain_id, d.apex
            FROM assets a
            JOIN domains d ON a.domain_id = d.id
            WHERE a.asset_value ILIKE :q OR a.ip_address ILIKE :q
            ORDER BY a.asset_value
            LIMIT 8
        """), {"q": q_like}).fetchall()
        cves = conn.execute(text("""
            SELECT DISTINCT a.asset_value AS host, d.id AS domain_id,
                            d.apex, c.cve_id
            FROM asset_cves c
            JOIN assets a ON a.id = c.asset_id
            JOIN domains d ON a.domain_id = d.id
            WHERE c.cve_id ILIKE :q
            ORDER BY c.cve_id
            LIMIT 8
        """), {"q": q_like}).fetchall()
    return hosts, cves


def _render_results(query):
    hosts, cves = _run_search(query)
    if not hosts and not cves:
        st.markdown(
            '<div class="omni-empty">No matches.</div>',
            unsafe_allow_html=True,
        )
        return
    for r in hosts:
        label = f"Host · {r.host}"
        if r.apex:
            label += f" ({r.apex})"
        if st.button(label, key=f"omni_h_{r.domain_id}_{r.host}",
                     width="stretch"):
            st.session_state.filter_domain_id = r.domain_id
            st.switch_page("pages/2_Targets.py")
    for r in cves:
        label = f"CVE · {r.cve_id} on {r.host}"
        if r.apex:
            label += f" ({r.apex})"
        if st.button(label, key=f"omni_c_{r.cve_id}_{r.domain_id}_{r.host}",
                     width="stretch"):
            st.session_state.filter_domain_id = r.domain_id
            st.switch_page("pages/2_Targets.py")


def render_universal_header():
    """Renders the static branding, nav, and search bar. Call first on every page."""
    
    # Brand Header
    st.markdown(
        '<div class="app-header">'
        '  <h1 class="app-title">DYNAMO</h1>'
        '  <p class="app-subtitle">EXTERNAL ATTACK SURFACE MANAGEMENT</p>'
        '</div>',
        unsafe_allow_html=True,
    )

    # Navigation Links
    nav_cols = st.columns(len(NAV_ITEMS))
    for i, (label, path) in enumerate(NAV_ITEMS):
        with nav_cols[i]:
            st.page_link(path, label=label, width="stretch")

    # Omnisearch (Full Width)
    with st.expander("Search hosts, IPs, CVEs", expanded=False):
        q = st.text_input(
            "omnisearch",
            placeholder="Search hosts, IPs, CVEs…",
            label_visibility="collapsed",
            key="_omnisearch_input",
        )
        if q and q.strip():
            _render_results(q.strip())