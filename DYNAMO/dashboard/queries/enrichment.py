import streamlit as st
import pandas as pd
from sqlalchemy import text

from storage.database import engine
from config.tools import AI_RISK_THRESHOLD as _DEFAULT_AI_RISK


@st.cache_data(ttl=15, show_spinner=False)
def pending_ai_count(domain_id: int | None = None, risk_min: int | None = None) -> int:
    if risk_min is None:
        risk_min = _DEFAULT_AI_RISK
    clauses = [
        "a.risk_score >= :risk_min",
        "a.is_active = TRUE",
        "(a.ai_analysis_json IS NULL OR a.ai_last_updated < a.last_seen)"
    ]
    params = {"risk_min": int(risk_min)}
    if domain_id is not None:
        clauses.append("a.domain_id = :domain_id")
        params["domain_id"] = int(domain_id)
    where = " AND ".join(clauses)
    df = pd.read_sql(
        text(f"SELECT COUNT(*) AS c FROM assets a WHERE {where}"),
        engine, params=params,
    )
    return int(df.iloc[0]["c"]) if not df.empty else 0


@st.cache_data(ttl=15, show_spinner=False)
def enriched_count(domain_id: int | None = None) -> int:
    clauses = ["a.ai_analysis_json IS NOT NULL"]
    params = {}
    if domain_id is not None:
        clauses.append("a.domain_id = :domain_id")
        params["domain_id"] = int(domain_id)
    where = " AND ".join(clauses)
    df = pd.read_sql(
        text(f"SELECT COUNT(*) AS c FROM assets a WHERE {where}"),
        engine, params=params,
    )
    return int(df.iloc[0]["c"]) if not df.empty else 0


@st.cache_data(ttl=15, show_spinner=False)
def pending_ai_list(domain_id: int | None = None,
                    risk_min: int | None = None, limit: int = 200) -> pd.DataFrame:
    if risk_min is None:
        risk_min = _DEFAULT_AI_RISK
        
    clauses = [
        "a.risk_score >= :risk_min",
        "a.is_active = TRUE",
        "(a.ai_analysis_json IS NULL OR a.ai_last_updated < a.last_seen)"
    ]
    params = {"risk_min": int(risk_min), "limit": int(limit)}
    if domain_id is not None:
        clauses.append("a.domain_id = :domain_id")
        params["domain_id"] = int(domain_id)
    where = " AND ".join(clauses)
    return pd.read_sql(text(f"""
        SELECT
            a.id,
            a.asset_value AS host,
            a.risk_score,
            a.risk_summary,
            d.apex
        FROM assets a
        LEFT JOIN domains d ON d.id = a.domain_id
        WHERE {where}
        ORDER BY a.risk_score DESC, a.asset_value
        LIMIT :limit
    """), engine, params=params)