import streamlit as st


SEV = {
    "critical": "#991B1B",
    "high":     "#DC2626",
    "medium":   "#EA580C",
    "low":      "#CA8A04",
    "info":     "#2563EB",
}

RISK_COLORS = {
    "Critical": SEV["critical"],
    "High":     SEV["high"],
    "Medium":   SEV["medium"],
    "Low":      SEV["low"],
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


_LIGHT = """
:root {
    --bg: #F8FAFC;
    --bg-soft: #F1F5F9;
    --bg-softer: #E2E8F0;
    --surface: #FFFFFF;
    --surface-hover: #F8FAFC;
    --border: #E2E8F0;
    --border-strong: #CBD5E1;
    --text: #0F172A;
    --text-muted: #64748B;
    --text-soft: #334155;
    --accent: #6366F1;
    --accent-soft: #E0E7FF;
    --accent-strong: #4338CA;
    --mono-bg: #F1F5F9;

    --sev-critical: #991B1B;
    --sev-critical-bg: #FEE2E2;
    --sev-critical-text: #7F1D1D;
    --sev-high: #DC2626;
    --sev-high-bg: #FEE2E2;
    --sev-high-text: #B91C1C;
    --sev-medium: #EA580C;
    --sev-medium-bg: #FFEDD5;
    --sev-medium-text: #9A3412;
    --sev-low: #CA8A04;
    --sev-low-bg: #FEF9C3;
    --sev-low-text: #854D0E;
    --sev-info: #2563EB;
    --sev-info-bg: #DBEAFE;
    --sev-info-text: #1E40AF;
}
"""

_CSS = """
/* Hide Streamlit native chrome */
#MainMenu {visibility: hidden;}
header {visibility: hidden;}
[data-testid="stToolbar"] {display: none !important;}
[data-testid="stSidebar"] {display: none !important;}
[data-testid="stSidebarCollapsedControl"] {display: none !important;}

/* Remove dead whitespace */
.block-container {
    padding-top: 0.5rem !important;
    padding-bottom: 2rem !important;
    max-width: 100% !important;
}

html, body, .stApp {
    background-color: var(--bg);
    color: var(--text);
    font-feature-settings: "cv11", "ss01";
    font-variant-numeric: tabular-nums;
}

/* App Header Branding */
.app-header {
    padding: 0 0 6px 0;
    margin-bottom: 0;
}
.app-title {
    font-size: 28px !important;
    font-weight: 800 !important;
    color: var(--text) !important;
    margin: 0 !important;
    letter-spacing: -0.03em;
    line-height: 1.1 !important;
}
.app-subtitle {
    font-size: 11px;
    font-weight: 600;
    color: var(--text-muted);
    letter-spacing: 0.1em;
    text-transform: uppercase;
    margin: 2px 0 0 0;
}

/* Typography */
h1 { font-size: 26px !important; font-weight: 700 !important; color: var(--text) !important; margin: 0 0 4px 0 !important; padding: 2px 0 !important; letter-spacing: -0.015em; line-height: 1.3 !important; }
h2 { font-size: 15px !important; font-weight: 600 !important; color: var(--text) !important; margin: 0 0 8px 0 !important; letter-spacing: -0.005em; }
h3 { font-size: 13px !important; font-weight: 600 !important; color: var(--text) !important; margin: 0 0 6px 0 !important; }
h4 { font-size: 11px !important; font-weight: 600 !important; color: var(--text-muted) !important; text-transform: uppercase; letter-spacing: 0.06em; margin: 0 0 4px 0 !important; }

/* Top nav links with Purple Borders */
[data-testid="stPageLink-NavLink"] {
    border: 1px solid var(--accent) !important;
    background: transparent !important;
    border-radius: 6px !important;
    padding: 4px 12px !important;
    min-height: 32px !important;
    justify-content: center !important;
    font-size: 13px !important;
    font-weight: 600 !important;
    color: var(--accent) !important;
    transition: all 0.15s ease !important;
    margin: 0 4px !important;
}
[data-testid="stPageLink-NavLink"]:hover {
    background: var(--accent-soft) !important;
    color: var(--accent-strong) !important;
    border-color: var(--accent-strong) !important;
}
[data-testid="stPageLink-NavLink"][aria-current="page"] {
    background: var(--accent-soft) !important;
    color: var(--accent-strong) !important;
    border-color: var(--accent-strong) !important;
    font-weight: 700 !important;
    box-shadow: 0 0 0 1px var(--accent) !important;
}

/* Search bar distinct */
[data-testid="stExpander"] {
    border: 1px solid var(--border) !important;
    border-radius: 6px !important;
    background: var(--bg-soft) !important;
    box-shadow: none !important;
    margin-bottom: 0 !important;
}
[data-testid="stExpander"] details summary {
    padding: 4px 12px !important;
    font-size: 13px !important;
    font-weight: 500 !important;
    color: var(--text-muted) !important;
}
[data-testid="stExpander"] details summary:hover {
    color: var(--text) !important;
}

/* Section header */
.section-head {
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    padding: 0 0 6px 0;
    margin: 14px 0 10px 0;
    border-bottom: 1px solid var(--border);
}
.section-head .sec-title {
    font-size: 12px;
    font-weight: 700;
    color: var(--text);
    text-transform: uppercase;
    letter-spacing: 0.06em;
}
.section-head .sec-meta {
    font-size: 11px;
    color: var(--text-muted);
    font-weight: 500;
}

/* KPI cards */
.kpi-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-top: 3px solid var(--accent);
    border-radius: 8px;
    padding: 10px 12px 10px 12px;
    min-height: 68px;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    transition: border-color 0.15s ease;
    box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
}
.kpi-card:hover { border-color: var(--border-strong); }
.kpi-card.accent-critical { border-top-color: var(--sev-critical); }
.kpi-card.accent-high     { border-top-color: var(--sev-high); }
.kpi-card.accent-medium   { border-top-color: var(--sev-medium); }
.kpi-card.accent-low      { border-top-color: var(--sev-low); }
.kpi-card.accent-info     { border-top-color: var(--sev-info); }
.kpi-card.accent-neutral  { border-top-color: var(--border-strong); }

.kpi-head {
    display: flex;
    align-items: center;
    font-size: 10px;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.08em;
    font-weight: 700;
}
.kpi-head .kpi-dot {
    display: inline-block;
    width: 5px;
    height: 5px;
    border-radius: 50%;
    margin-right: 6px;
    background: var(--border-strong);
}
.kpi-card.accent-critical .kpi-dot { background: var(--sev-critical); }
.kpi-card.accent-high .kpi-dot     { background: var(--sev-high); }
.kpi-card.accent-medium .kpi-dot   { background: var(--sev-medium); }
.kpi-card.accent-low .kpi-dot      { background: var(--sev-low); }
.kpi-card.accent-info .kpi-dot     { background: var(--sev-info); }

.kpi-value {
    font-size: 26px;
    font-weight: 700;
    line-height: 1;
    color: var(--text);
    margin: 4px 0 0 0;
    letter-spacing: -0.025em;
}

.kpi-foot {
    font-size: 11px !important;
    color: var(--text-soft) !important;
    font-weight: 500;
    margin-top: 2px;
}

/* Pills */
.pill {
    display: inline-block;
    padding: 1px 7px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 700;
    line-height: 1.6;
    background: var(--sev-info-bg);
    color: var(--sev-info-text);
    font-variant-numeric: tabular-nums;
    min-width: 20px;
    text-align: center;
}
.pill-critical { background: var(--sev-critical); color: #FFFFFF; }
.pill-high     { background: var(--sev-high);     color: #FFFFFF; }
.pill-medium   { background: var(--sev-medium);   color: #FFFFFF; }
.pill-low      { background: var(--sev-low);      color: #FFFFFF; }
.pill-info     { background: var(--sev-info);     color: #FFFFFF; }

/* Severity strip */
.sev-strip {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 10px 14px;
    margin: 14px 0 4px 0;
    box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
}
.sev-strip-bar {
    display: flex;
    height: 5px;
    border-radius: 3px;
    overflow: hidden;
    background: var(--border);
    margin-bottom: 8px;
}
.sev-strip-bar span {
    display: block;
    height: 100%;
}
.sev-seg-critical { background: var(--sev-critical); }
.sev-seg-high     { background: var(--sev-high); }
.sev-seg-medium   { background: var(--sev-medium); }
.sev-seg-low      { background: var(--sev-low); }
.sev-seg-info     { background: var(--sev-info); }

.sev-legend {
    display: flex;
    gap: 16px;
    font-size: 11px;
    color: var(--text-muted);
    flex-wrap: wrap;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    font-weight: 600;
}
.sev-legend b {
    color: var(--text);
    font-weight: 700;
    font-variant-numeric: tabular-nums;
    margin-right: 4px;
}
.sev-legend .sev-legend-item {
    display: inline-flex;
    align-items: center;
    gap: 4px;
}
.sev-legend .dot {
    display: inline-block;
    width: 6px;
    height: 6px;
    border-radius: 50%;
    margin-right: 5px;
}
.dot-critical { background: var(--sev-critical); }
.dot-high     { background: var(--sev-high); }
.dot-medium   { background: var(--sev-medium); }
.dot-low      { background: var(--sev-low); }
.dot-info     { background: var(--sev-info); }

/* Domains table */
.dyn-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    overflow: hidden;
    box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
}
.dyn-table thead th {
    text-align: left;
    font-size: 10px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: var(--text-muted);
    background: var(--bg-soft);
    padding: 9px 14px;
    border-bottom: 1px solid var(--border);
}
.dyn-table tbody td {
    padding: 11px 14px;
    border-bottom: 1px solid var(--border);
    color: var(--text);
    vertical-align: middle;
}
.dyn-table tbody tr:last-child td { border-bottom: none; }
.dyn-table tbody tr:hover { background: var(--surface-hover); }

.dyn-table .host-cell {
    font-family: 'SF Mono', 'Menlo', 'Consolas', monospace;
    font-size: 12.5px;
    font-weight: 500;
    color: var(--text);
}
.dyn-table .num-cell {
    font-variant-numeric: tabular-nums;
    font-weight: 700;
    color: var(--text);
    font-size: 13px;
}
.dyn-table .dist-cell {
    display: flex;
    gap: 5px;
    flex-wrap: wrap;
}

/* Finding cards */
.finding {
    background: var(--surface);
    border: 1px solid var(--border);
    border-left: 3px solid var(--sev-info);
    border-radius: 6px;
    padding: 10px 14px;
    margin-bottom: 6px;
    transition: background 0.15s ease;
    box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
}
.finding:hover { background: var(--surface-hover); }
.finding.sev-critical { border-left-color: var(--sev-critical); }
.finding.sev-high     { border-left-color: var(--sev-high); }
.finding.sev-medium   { border-left-color: var(--sev-medium); }
.finding.sev-low      { border-left-color: var(--sev-low); }

.finding-top {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 5px;
    flex-wrap: wrap;
}
.finding-host {
    font-family: 'SF Mono', 'Menlo', 'Consolas', monospace;
    font-size: 12.5px;
    font-weight: 600;
    color: var(--text);
}
.finding-source {
    font-size: 9px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--text-muted);
    padding: 1px 6px;
    border: 1px solid var(--border);
    border-radius: 3px;
    background: var(--bg-soft);
}
.finding-title {
    font-size: 13px;
    color: var(--text);
    line-height: 1.45;
    font-weight: 500;
}
.finding-meta {
    font-family: 'SF Mono', 'Menlo', 'Consolas', monospace;
    font-size: 11.5px;
    color: var(--text-muted);
    margin-top: 4px;
    word-break: break-all;
}

/* Breadcrumb */
.breadcrumb {
    font-size: 11px;
    color: var(--text-muted);
    margin: 0 0 6px 0;
    padding: 0;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    font-weight: 600;
}
.breadcrumb a { color: var(--text-muted); text-decoration: none; }
.breadcrumb a:hover { color: var(--accent); }
.breadcrumb .sep { margin: 0 7px; opacity: 0.4; }
.breadcrumb .current { color: var(--text); }

/* Captions */
.dyn-caption {
    color: var(--text-muted);
    font-size: 12px;
    line-height: 1.5;
    margin: 0;
}

/* Form controls */
div[data-baseweb="input"] > div,
div[data-baseweb="select"] > div,
div[data-baseweb="textarea"] > div,
div[data-baseweb="base-input"] > div {
    border: 1px solid var(--border-strong) !important;
    border-radius: 6px !important;
    background-color: var(--surface) !important;
    box-shadow: none !important;
}
div[data-baseweb="input"] > div:hover,
div[data-baseweb="select"] > div:hover,
div[data-baseweb="textarea"] > div:hover {
    border-color: var(--accent) !important;
}
div[data-baseweb="input"] > div:focus-within,
div[data-baseweb="select"] > div:focus-within,
div[data-baseweb="textarea"] > div:focus-within {
    border-color: var(--accent) !important;
    box-shadow: 0 0 0 3px var(--accent-soft) !important;
}
input, textarea {
    color: var(--text) !important;
    background: transparent !important;
}
label, .stTextInput label, .stSelectbox label,
.stRadio label, .stMultiSelect label, .stSlider label {
    color: var(--text-soft) !important;
    font-size: 12px !important;
    font-weight: 600 !important;
    letter-spacing: 0.01em !important;
}

/* Multiselect tags */
span[data-baseweb="tag"] {
    background-color: var(--accent-soft) !important;
    color: var(--accent-strong) !important;
    border-radius: 4px !important;
    font-weight: 600 !important;
}

/* Buttons */
.stButton > button, .stDownloadButton > button {
    background: var(--surface) !important;
    color: var(--text) !important;
    border: 1px solid var(--border-strong) !important;
    border-radius: 6px !important;
    font-weight: 600 !important;
    font-size: 12.5px !important;
    padding: 4px 12px !important;
    min-height: 28px !important;
    box-shadow: none !important;
    letter-spacing: 0.01em !important;
    text-transform: none !important;
}
.stButton > button:hover, .stDownloadButton > button:hover {
    background: var(--surface-hover) !important;
    border-color: var(--accent) !important;
    color: var(--accent) !important;
}
.stButton > button[kind="primary"] {
    background: var(--accent) !important;
    color: #FFFFFF !important;
    border-color: var(--accent) !important;
}
.stButton > button[kind="primary"]:hover {
    background: var(--accent-strong) !important;
    border-color: var(--accent-strong) !important;
    color: #FFFFFF !important;
}

/* Tabs */
.stTabs [data-baseweb="tab-list"] {
    border-bottom: 1px solid var(--border);
    gap: 0;
}
.stTabs [data-baseweb="tab"] {
    color: var(--text-muted) !important;
    font-weight: 600 !important;
    font-size: 12.5px !important;
    padding: 10px 16px !important;
    border-radius: 0 !important;
    letter-spacing: 0.01em !important;
}
.stTabs [aria-selected="true"] {
    color: var(--text) !important;
    border-bottom: 2px solid var(--accent) !important;
    background: transparent !important;
}

/* Dataframes */
div[data-testid="stDataFrame"] {
    border: 1px solid var(--border) !important;
    border-radius: 8px !important;
    overflow: hidden;
}

/* Divider */
hr {
    border: none;
    border-top: 1px solid var(--border);
    margin: 14px 0;
}

/* Radio / checkbox accent */
.stRadio [data-baseweb="radio"] div[aria-checked="true"] > div:first-child {
    background-color: var(--accent) !important;
    border-color: var(--accent) !important;
}
.stCheckbox [data-baseweb="checkbox"] div[aria-checked="true"] > div:first-child {
    background-color: var(--accent) !important;
    border-color: var(--accent) !important;
}

/* Omnisearch result area */
.omni-empty {
    color: var(--text-muted);
    font-size: 12px;
    padding: 8px 12px;
    border: 1px dashed var(--border);
    border-radius: 8px;
    margin-top: 6px;
}

/* Branded empty / error states */
.empty-state {
    text-align: center;
    padding: 48px 24px;
    background: var(--surface);
    border: 1px dashed var(--border);
    border-radius: 8px;
    margin: 20px 0;
}
.empty-state.empty-error {
    border-color: var(--sev-high);
    background: var(--sev-high-bg);
}
.empty-icon {
    font-size: 32px;
    color: var(--text-muted);
    margin-bottom: 8px;
}
.empty-error .empty-icon {
    color: var(--sev-high);
}
.empty-title {
    font-size: 15px;
    font-weight: 700;
    color: var(--text);
    margin-bottom: 6px;
}
.empty-body {
    font-size: 12.5px;
    color: var(--text-muted);
    max-width: 480px;
    margin: 0 auto 4px auto;
    line-height: 1.5;
}

/* KPI delta badge */
.kpi-delta {
    display: inline-block;
    font-size: 10px;
    font-weight: 700;
    padding: 1px 6px;
    border-radius: 4px;
    margin-top: 4px;
    font-variant-numeric: tabular-nums;
}
.kpi-delta.up   { background: var(--sev-high-bg);     color: var(--sev-high-text); }
.kpi-delta.down { background: var(--sev-low-bg);      color: var(--sev-low-text); }
.kpi-delta.flat { background: var(--bg-soft);         color: var(--text-muted); }

/* Scan stepper */
.stepper {
    display: flex;
    gap: 4px;
    flex-wrap: wrap;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 12px 14px;
    margin: 8px 0;
}
.step {
    flex: 1;
    min-width: 80px;
    text-align: center;
    padding: 6px 4px;
    border-radius: 6px;
    background: var(--bg-soft);
    border: 1px solid var(--border);
    font-size: 10.5px;
    font-weight: 600;
    color: var(--text-muted);
    transition: all 0.2s ease;
}
.step .step-dot {
    display: block;
    margin-bottom: 2px;
    font-size: 14px;
}
.step.done   { border-color: var(--sev-info); color: var(--sev-info-text); background: var(--sev-info-bg); }
.step.running { border-color: var(--accent); color: var(--accent-strong); background: var(--accent-soft); }
.step.failed { border-color: var(--sev-high); color: var(--sev-high-text); background: var(--sev-high-bg); }
.step.cached { border-color: var(--sev-low); color: var(--sev-low-text); background: var(--sev-low-bg); }

/* Unified radii */
.kpi-card, .finding, .dyn-table, .sev-strip,
div[data-testid="stExpander"], div[data-testid="stDataFrame"] {
    border-radius: 8px !important;
}

/* Reviewed finding marker */
.finding.reviewed { opacity: 0.45; border-left-color: var(--border-strong); }

"""

def apply_theme():
    st.markdown(f"<style>{_LIGHT}\n{_CSS}</style>", unsafe_allow_html=True)


def severity_color(sev: str) -> str:
    return SEV.get((sev or "info").lower(), SEV["info"])


def risk_label(score: int):
    if score >= 80: return "sev-critical", "Critical"
    if score >= 50: return "sev-high", "High"
    if score >= 20: return "sev-medium", "Medium"
    return "sev-low", "Low"

SEV_ICON = {
    "critical": "◆",
    "high":     "▲",
    "medium":   "●",
    "low":      "■",
    "info":     "○",
}

def sev_badge(text, severity):
    sev = (severity or "info").lower()
    icon = SEV_ICON.get(sev, "○")
    return f'<span class="pill pill-{sev}">{icon} {text}</span>'