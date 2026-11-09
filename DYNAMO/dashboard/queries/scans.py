import pandas as pd
import streamlit as st
from sqlalchemy import text
from storage.database import engine


def _fmt_dt_cols(df, *cols):
    for c in cols:
        if c in df.columns:
            df[c] = pd.to_datetime(df[c], errors="coerce").dt.strftime("%d-%m-%Y %H:%M:%S")
    return df

@st.cache_data(ttl=30, show_spinner=False)
def get_scans():
    query = """
    SELECT s.id, s.target, s.mode, s.started_at, s.completed_at, s.status,
           s.subfinder_count, s.crt_count, s.gau_count, s.wayback_count,
           s.httpx_count, s.nmap_ip_count, s.nmap_service_count,
           s.katana_count, s.ffuf_count, s.nuclei_count, s.sqli_count,
           s.saved_asset_count,
           COUNT(DISTINCT CASE WHEN a.is_active = true THEN a.id END) AS active_assets
    FROM scans s
    LEFT JOIN scan_assets sa ON s.id = sa.scan_id
    LEFT JOIN assets a ON sa.asset_id = a.id
    GROUP BY s.id, s.target, s.mode, s.started_at, s.completed_at, s.status,
             s.subfinder_count, s.crt_count, s.gau_count, s.wayback_count,
             s.httpx_count, s.nmap_ip_count, s.nmap_service_count,
             s.katana_count, s.ffuf_count, s.nuclei_count, s.sqli_count,
             s.saved_asset_count
    ORDER BY s.started_at DESC
    """
    df = pd.read_sql(query, engine)
    return _fmt_dt_cols(df, "started_at", "completed_at")

def scan_deltas(target):
    import pandas as pd
    from sqlalchemy import text
    from storage.database import engine

    sql = text("""
        SELECT id, completed_at, correlated_asset_count, saved_asset_count,
               nuclei_count, vapt_count, sqli_count
        FROM scans
        WHERE target = :target
          AND status IN ('completed', 'partial')
        ORDER BY completed_at DESC NULLS LAST
        LIMIT 2
    """)
    df = pd.read_sql(sql, engine, params={"target": target})
    if len(df) < 2:
        return {}
    cur, prev = df.iloc[0], df.iloc[1]
    return {
        "assets": int(cur["saved_asset_count"] or 0) - int(prev["saved_asset_count"] or 0),
        "nuclei": int(cur["nuclei_count"] or 0) - int(prev["nuclei_count"] or 0),
        "vapt":   int(cur["vapt_count"] or 0) - int(prev["vapt_count"] or 0),
        "sqli":   int(cur["sqli_count"] or 0) - int(prev["sqli_count"] or 0),
    }


@st.cache_data(ttl=3, show_spinner=False)
def scan_phase_progress(scan_id):
    import pandas as pd
    from sqlalchemy import text
    from storage.database import engine

    df = pd.read_sql(text("""
        SELECT phase, status, count
        FROM scan_progress
        WHERE scan_id = :sid
        ORDER BY id
    """), engine, params={"sid": int(scan_id)})
    return df