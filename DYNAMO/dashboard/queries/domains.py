import streamlit as st
import pandas as pd
from sqlalchemy import text
from storage.database import engine


def _fmt_dt_cols(df, *cols):
    import pandas as pd
    for c in cols:
        if c in df.columns:
            df[c] = pd.to_datetime(df[c], errors="coerce").dt.strftime("%d-%m-%Y %H:%M:%S")
    return df

@st.cache_data(ttl=60, show_spinner=False)
def get_domains() -> pd.DataFrame:

    sql = text("""
        SELECT
            d.id                              AS domain_id,
            d.apex,
            d.first_seen,
            d.last_seen,
            d.is_active,
            COUNT(DISTINCT CASE WHEN a.is_active THEN a.id END) AS active_assets,
            COUNT(DISTINCT a.id)                                AS total_assets
        FROM domains d
        LEFT JOIN domain_assets da ON da.domain_id = d.id
        LEFT JOIN assets a         ON a.id = da.asset_id
        GROUP BY d.id, d.apex, d.first_seen, d.last_seen, d.is_active
        ORDER BY d.apex
    """)
    df = pd.read_sql(sql, engine)
    return _fmt_dt_cols(df, "first_seen", "last_seen")


def get_assets_for_domain(domain_id: int,
                          only_active: bool = True,
                          risk_min: int = 0,
                          search: str = "") -> pd.DataFrame:
    """
    Server-side filtered assets for one apex.
    """
    clauses = ["a.domain_id = :domain_id"]
    params  = {"domain_id": int(domain_id)}

    if only_active:
        clauses.append("a.is_active = TRUE")
    if risk_min > 0:
        clauses.append("a.risk_score >= :risk_min")
        params["risk_min"] = int(risk_min)
    if search:
        clauses.append("(LOWER(a.asset_value) LIKE :q OR LOWER(COALESCE(a.title,'')) LIKE :q)")
        params["q"] = f"%{search.lower()}%"

    where = " AND ".join(clauses)

    sql = text(f"""
        SELECT
            a.id, a.asset_value, a.url, a.ip_address, a.status_code,
            a.title, a.technologies, a.risk_score, a.risk_summary,
            a.first_seen, a.last_seen, a.is_active
        FROM assets a
        WHERE {where}
        ORDER BY a.risk_score DESC, a.asset_value
    """)
    df = pd.read_sql(sql, engine, params=params)
    return _fmt_dt_cols(df, "first_seen", "last_seen")
