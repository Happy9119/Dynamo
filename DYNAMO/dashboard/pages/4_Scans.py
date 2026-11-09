import os
import sys
from datetime import datetime
from pathlib import Path

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(os.path.dirname(_HERE))
_DASH = os.path.dirname(_HERE)
for _p in (_ROOT, _DASH):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import streamlit as st

from _theme import apply_theme
from components.topbar import render_universal_header
from components.cards import section_head
from queries.scans import get_scans
from core.domain_utils import extract_apex


st.set_page_config(page_title="Scan Output", page_icon=None, layout="wide", initial_sidebar_state="collapsed")
apply_theme()

# 1. Render Header
render_universal_header()

scans = get_scans()
if scans.empty:
    st.info("No scans yet. Run one from Launchpad first.")
    st.stop()

labels = {
    f"#{int(r['id'])} — {r['target']} ({r['mode']}, {r['status']}) — {r['started_at']}": int(r["id"])
    for _, r in scans.iterrows()
}
picked = st.selectbox("Select a scan", list(labels.keys()), label_visibility="collapsed")
scan_id = labels[picked]

scan_row = scans[scans["id"] == scan_id].iloc[0]
apex = extract_apex(scan_row["target"]) or scan_row["target"].lower()

run_dir = Path(_ROOT) / "runs" / apex / str(scan_id)
c1, c2, c3, c4 = st.columns(4)
with c1:
    st.metric("Scan", f"#{scan_id}")
with c2:
    st.metric("Mode", scan_row["mode"])
with c3:
    st.metric("Status", scan_row["status"])
with c4:
    st.metric("Apex", apex)

if not run_dir.exists():
    st.warning(
        "No artifacts on disk for this scan. This scan was run before the "
        "artifact writer was enabled, or files were deleted."
    )
    st.code(f"Expected path: {run_dir.resolve()}", language="text")
    st.stop()

files = sorted(p for p in run_dir.rglob("*") if p.is_file())
if not files:
    st.warning("Run directory exists but is empty.")
    st.stop()

section_head(f"Files ({len(files)})")

search = st.text_input(
    "Filter by name",
    placeholder="e.g. nuclei, katana, sqlmap",
    key="scan_output_filter",
    label_visibility="collapsed"
)
rel_paths = [str(p.relative_to(run_dir)) for p in files]
if search:
    rel_paths = [p for p in rel_paths if search.lower() in p.lower()]

if not rel_paths:
    st.info("No files match the filter.")
    st.stop()

selected = st.selectbox("Open file", rel_paths, key="scan_output_pick")
file_path = run_dir / selected

stat = file_path.stat()
content = file_path.read_text(errors="replace")
line_count = content.count("\n") + (1 if content and not content.endswith("\n") else 0)

c1, c2, c3 = st.columns(3)
with c1:
    st.metric("Size", f"{stat.st_size:,} B")
with c2:
    st.metric("Lines", line_count)
with c3:
    st.metric("Modified", datetime.fromtimestamp(stat.st_mtime).strftime("%d-%m-%Y %H:%M:%S"))

if len(content) > 200_000:
    content = content[:200_000] + f"\n\n... (truncated at 200 KB; {stat.st_size:,} B total)"

st.code(content or "(empty)", language="text")

st.download_button(
    "Download this file",
    data=file_path.read_bytes(),
    file_name=selected.split("/")[-1],
    width='stretch',
)

with st.expander("Download the full scan as a zip"):
    import io
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in files:
            zf.write(f, f.relative_to(run_dir))
    st.download_button(
        "Download ZIP",
        data=buf.getvalue(),
        file_name=f"dynamo_scan_{scan_id}_{apex}.zip",
        width='stretch',
    )