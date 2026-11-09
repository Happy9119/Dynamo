import html
import streamlit as st
import hashlib

def _safe(v, default=""):
    if v is None:
        return default
    s = str(v).strip()
    if not s or s.lower() in ("none", "nan", "<na>", "nat"):
        return default
    return s

def _esc(v):
    return html.escape(str(v), quote=True)

def page_header(title, subtitle=None, brand=False):
    title_cls = "app-title" if brand else "page-title"
    sub_cls = "app-subtitle" if brand else "page-subtitle"
    sub_html = f'<p class="{sub_cls}">{_esc(subtitle)}</p>' if subtitle else ""
    html_str = (
        f'<div class="page-header">'
        f'  <div>'
        f'    <h1 class="{title_cls}">{_esc(title)}</h1>'
        f'    {sub_html}'
        f'  </div>'
        f'</div>'
    )
    st.markdown(html_str, unsafe_allow_html=True)

def section_head(title, meta=None):
    meta_html = f'<span class="sec-meta">{_esc(meta)}</span>' if meta else ""
    html_str = (
        f'<div class="section-head">'
        f'  <span class="sec-title">{_esc(title)}</span>'
        f'  {meta_html}'
        f'</div>'
    )
    st.markdown(html_str, unsafe_allow_html=True)

def kpi_card(label, value, foot=None, accent=None, dot=True, delta=None):
    cls = f"accent-{accent}" if accent else "accent-neutral"
    dot_html = '<span class="kpi-dot"></span>' if dot else ""
    foot_html = f'<div class="kpi-foot">{_esc(foot)}</div>' if foot else ""
    delta_html = ""
    if delta is not None:
        try:
            d = int(delta)
        except (TypeError, ValueError):
            d = 0
        if d > 0:
            delta_html = f'<div class="kpi-delta up">▲ +{d}</div>'
        elif d < 0:
            delta_html = f'<div class="kpi-delta down">▼ {d}</div>'
        else:
            delta_html = '<div class="kpi-delta flat">— no change</div>'
    html_str = (
        f'<div class="kpi-card {cls}">'
        f'  <div class="kpi-head">{dot_html}{_esc(label)}</div>'
        f'  <div class="kpi-value">{_esc(value)}</div>'
        f'  {foot_html}{delta_html}'
        f'</div>'
    )
    st.markdown(html_str, unsafe_allow_html=True)

def pill(text, severity, title=None):
    sev = (severity or "info").lower()
    cls = f"pill-{sev}" if sev in ("critical", "high", "medium", "low") else "pill"
    title_attr = f'title="{_esc(title)}"' if title else ""
    return f'<span class="pill {cls}" {title_attr}>{_esc(text)}</span>'

def severity_strip(counts: dict):
    order = ["critical", "high", "medium", "low", "info"]
    total = sum(int(counts.get(k, 0)) for k in order)

    if total == 0:
        st.markdown(
            '<div class="sev-strip">'
            '<div class="sev-strip-bar"><span class="sev-seg-info" '
            'style="flex:1"></span></div>'
            '<div class="sev-legend"><span class="sev-legend-item">'
            'No findings yet</span></div>'
            '</div>',
            unsafe_allow_html=True,
        )
        return

    segs = "".join(
        f'<span class="sev-seg-{k}" style="flex:{int(counts.get(k, 0))}"></span>'
        for k in order if int(counts.get(k, 0)) > 0
    )

    legend = "".join(
        f'<span class="sev-legend-item">'
        f'<span class="dot dot-{k}"></span>'
        f'<b>{int(counts.get(k, 0))}</b> {_esc(k)}'
        f'</span>'
        for k in order
    )

    html_str = (
        f'<div class="sev-strip">'
        f'  <div class="sev-strip-bar">{segs}</div>'
        f'  <div class="sev-legend">{legend}<span style="margin-left:auto;font-weight:700;color:var(--text);">{total} total</span></div>'
        f'</div>'
    )
    st.markdown(html_str, unsafe_allow_html=True)

def finding_card(severity, host, title, source=None, url=None, detail=None,
                 evidence=None, idx=0, finding_key=None):
    sev = (severity or "info").lower()
    host_txt = _safe(host, "unknown")
    title_txt = _safe(title, "finding")
    source_html = (f'<span class="finding-source">{_esc(source).upper()}</span>'
                   if source else "")

    reviewed = False
    if finding_key:
        reviewed_set = st.session_state.get("reviewed_findings", set())
        reviewed = finding_key in reviewed_set

    meta_html = ""
    if url:
        meta_html = f'<div class="finding-meta">{_esc(url)}</div>'
    elif detail:
        meta_html = f'<div class="finding-meta">{_esc(detail)}</div>'

    extra_cls = " reviewed" if reviewed else ""
    html_str = (
        f'<div class="finding sev-{sev}{extra_cls}">'
        f'  <div class="finding-top">'
        f'    <span class="pill pill-{sev}">{_esc(sev)}</span>'
        f'    <span class="finding-host">{_esc(host_txt)}</span>'
        f'    {source_html}'
        f'  </div>'
        f'  <div class="finding-title">{_esc(title_txt)}</div>'
        f'  {meta_html}'
        f'</div>'
    )
    st.markdown(html_str, unsafe_allow_html=True)

    if not finding_key and not evidence:
        return

    btn_suffix = hashlib.sha256(
        f"{finding_key}|{host_txt}|{title_txt}|{evidence or ''}|"
        f"{url or ''}|{detail or ''}|{idx}".encode()
    ).hexdigest()[:16]

    action_cols = st.columns([1, 1, 1, 4])
    with action_cols[0]:
        if finding_key:
            if reviewed:
                if st.button("Unmark", key=f"unmark_{btn_suffix}", width="content"):
                    s = st.session_state.get("reviewed_findings", set())
                    s.discard(finding_key)
                    st.session_state.reviewed_findings = s
                    st.rerun()
            else:
                if st.button("Mark reviewed", key=f"mark_{btn_suffix}", width="content"):
                    s = st.session_state.get("reviewed_findings", set())
                    s.add(finding_key)
                    st.session_state.reviewed_findings = s
                    st.rerun()
    with action_cols[1]:
        if evidence:
            if st.button("Show evidence", key=f"ev_{btn_suffix}", width="content"):
                st.session_state[f"show_ev_{btn_suffix}"] = not st.session_state.get(f"show_ev_{btn_suffix}", False)
    with action_cols[2]:
        if evidence:
            if st.button("Ask AI", key=f"ai_{btn_suffix}", width="content"):
                from core.ai_engine import explain_finding
                with st.spinner("Asking AI..."):
                    response = explain_finding(title, f"Host: {host}\nEvidence: {evidence}")
                    st.session_state[f"ai_resp_{btn_suffix}"] = response

    if evidence and st.session_state.get(f"show_ev_{btn_suffix}", False):
        st.code(evidence, language="text")
    if st.session_state.get(f"ai_resp_{btn_suffix}"):
        st.info(st.session_state[f"ai_resp_{btn_suffix}"])

def domains_table(rows):
    body = []
    for r in rows:
        dist = ""
        for k in ("critical", "high", "medium", "low"):
            v = int(r.get(k, 0))
            if v > 0:
                dist += pill(v, k, title=f"{v} {k}")
        if not dist:
            dist = '<span style="color:var(--text-muted);font-size:12px;">&mdash;</span>'

        risk_score = r.get("risk_score", 0)
        
        body.append(
            f'<tr>'
            f'  <td class="host-cell">{_esc(_safe(r.get("domain")))}</td>'
            f'  <td class="num-cell">{int(r.get("assets", 0))}</td>'
            f'  <td class="num-cell">{int(r.get("findings", 0))}</td>'
            f'  <td class="num-cell" style="color:var(--accent);">{risk_score}</td>'
            f'  <td><div class="dist-cell">{dist}</div></td>'
            f'</tr>'
        )

    html_str = (
        f'<table class="dyn-table">'
        f'  <thead><tr>'
        f'    <th>Domain</th>'
        f'    <th style="width:80px;">Assets</th>'
        f'    <th style="width:80px;">Findings</th>'
        f'    <th style="width:80px;">Risk</th>'
        f'    <th>Distribution</th>'
        f'  </tr></thead>'
        f'  <tbody>{"".join(body)}</tbody>'
        f'</table>'
    )
    st.markdown(html_str, unsafe_allow_html=True)