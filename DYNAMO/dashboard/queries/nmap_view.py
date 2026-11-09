from pathlib import Path

import pandas as pd

from core.validators import is_safe_path_component


NMAP_ROOT = Path("nmap_outputs").resolve()
MAX_BYTES = 2_000_000


def _safe_dir(apex):
    if not is_safe_path_component(apex):
        return None
    d = (NMAP_ROOT / apex).resolve()
    try:
        d.relative_to(NMAP_ROOT)
    except ValueError:
        return None
    if not d.is_dir():
        return None
    return d


def list_nmap_files(apex):
    d = _safe_dir(apex)
    if d is None:
        return []
    return sorted([p for p in d.iterdir()
                   if p.is_file() and p.suffix == ".txt"])


def read_nmap_file(path, max_lines=2000):
    p = Path(path).resolve()
    try:
        p.relative_to(NMAP_ROOT)
    except ValueError:
        return ""
    if not p.is_file():
        return ""

    size = p.stat().st_size
    with p.open("r", errors="replace") as f:
        content = f.read(MAX_BYTES)

    truncated_by_bytes = size > MAX_BYTES
    lines = content.splitlines()

    if len(lines) > max_lines:
        body = "\n".join(lines[:max_lines])
        body += f"\n\n... ({len(lines) - max_lines} more lines omitted)"
    else:
        body = "\n".join(lines)

    if truncated_by_bytes:
        body += f"\n\n... (file truncated at {MAX_BYTES // 1024} KB)"

    return body


import re as _re

_SCAN_SUFFIX = _re.compile(r"^(.+?)_scan(\d+)$")


def nmap_files_df(apex):
    files = list_nmap_files(apex)
    if not files:
        return pd.DataFrame(columns=["ip", "scan_id", "path", "size_kb"])

    rows = []
    for p in files:
        m = _SCAN_SUFFIX.match(p.stem)
        if m:
            ip, scan_id = m.group(1), int(m.group(2))
        else:
            ip, scan_id = p.stem, None
        rows.append({
            "ip": ip,
            "scan_id": scan_id,
            "path": str(p),
            "size_kb": round(p.stat().st_size / 1024, 1),
        })

    df = pd.DataFrame(rows)
    df = df.sort_values(
        by=["ip", "scan_id"],
        ascending=[True, False],
        na_position="last",
    ).reset_index(drop=True)
    return df



