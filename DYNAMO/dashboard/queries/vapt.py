import pandas as pd
from sqlalchemy import text
from storage.database import engine


def _fmt_dt_cols(df, *cols):
    for c in cols:
        if c in df.columns:
            df[c] = pd.to_datetime(df[c], errors="coerce").dt.strftime("%d-%m-%Y %H:%M:%S")
    return df

def list_vapt_findings(domain_id=None, active_only=True, limit=5000):
    clauses = ["1=1"]
    params = {"limit": int(limit)}
    if domain_id is not None:
        clauses.append("a.domain_id = :domain_id")
        params["domain_id"] = int(domain_id)
    if active_only:
        clauses.append("a.is_active = TRUE")
    where = " AND ".join(clauses)

    sql = text(f"""
        SELECT
            a.asset_value AS host,
            a.ip_address,
            v.vuln_type,
            v.severity,
            v.url,
            v.parameter,
            v.evidence,
            v.remediation,
            a.risk_score,
            v.detected_at
        FROM asset_vulns v
        JOIN assets a ON a.id = v.asset_id
        WHERE {where}
        ORDER BY
            CASE LOWER(v.severity)
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
                ELSE 5
            END,
            a.asset_value
        LIMIT :limit
    """)
    df = pd.read_sql(sql, engine, params=params)
    return _fmt_dt_cols(df, "detected_at")


def vapt_severity_counts(domain_id=None, active_only=True):
    clauses = ["1=1"]
    params = {}
    if domain_id is not None:
        clauses.append("a.domain_id = :domain_id")
        params["domain_id"] = int(domain_id)
    if active_only:
        clauses.append("a.is_active = TRUE")
    where = " AND ".join(clauses)

    sql = text(f"""
        SELECT v.severity AS severity, COUNT(*) AS count
        FROM asset_vulns v
        JOIN assets a ON a.id = v.asset_id
        WHERE {where}
        GROUP BY v.severity
    """)
    got = pd.read_sql(sql, engine, params=params)
    order = ["critical", "high", "medium", "low", "info"]
    got = got.set_index("severity").reindex(order, fill_value=0).reset_index()
    return got


def vapt_type_counts(domain_id=None, active_only=True, top=15):
    clauses = ["1=1"]
    params = {"top": int(top)}
    if domain_id is not None:
        clauses.append("a.domain_id = :domain_id")
        params["domain_id"] = int(domain_id)
    if active_only:
        clauses.append("a.is_active = TRUE")
    where = " AND ".join(clauses)

    sql = text(f"""
        SELECT v.vuln_type AS vuln_type, COUNT(*) AS count
        FROM asset_vulns v
        JOIN assets a ON a.id = v.asset_id
        WHERE {where}
        GROUP BY v.vuln_type
        ORDER BY COUNT(*) DESC
        LIMIT :top
    """)
    return pd.read_sql(sql, engine, params=params)