import pandas as pd
from sqlalchemy import text
from storage.database import engine


def _fmt_dt_cols(df, *cols):
    import pandas as pd
    for c in cols:
        if c in df.columns:
            df[c] = pd.to_datetime(df[c], errors="coerce").dt.strftime("%d-%m-%Y %H:%M:%S")
    return df

def _where_domain(domain_id=None, active_only=True):
    clauses = ["1=1"]
    params = {}
    if domain_id is not None:
        clauses.append("a.domain_id = :domain_id")
        params["domain_id"] = int(domain_id)
    if active_only:
        clauses.append("a.is_active = TRUE")
    return " AND ".join(clauses), params


def list_ips(domain_id=None, active_only=True, limit=5000):
    where, params = _where_domain(domain_id, active_only)
    params["limit"] = int(limit)
    sql = text(f"""
        SELECT
            i.ip_address AS ip,
            a.asset_value AS host,
            a.risk_score,
            i.first_seen,
            i.last_seen,
            i.is_active
        FROM asset_ips i
        JOIN assets a ON a.id = i.asset_id
        WHERE {where}
        ORDER BY i.ip_address, a.asset_value
        LIMIT :limit
    """)
    df = pd.read_sql(sql, engine, params=params)
    return _fmt_dt_cols(df, "first_seen", "last_seen")


def list_services(domain_id=None, active_only=True, limit=5000):
    where, params = _where_domain(domain_id, active_only)
    params["limit"] = int(limit)
    sql = text(f"""
        SELECT
            a.asset_value AS host,
            a.ip_address AS ip,
            s.port,
            s.protocol,
            s.service_name,
            s.product,
            s.version,
            a.risk_score
        FROM services s
        JOIN assets a ON a.id = s.asset_id
        WHERE {where}
        ORDER BY s.port, a.asset_value
        LIMIT :limit
    """)
    return pd.read_sql(sql, engine, params=params)


def list_cves(domain_id=None, active_only=True, limit=5000):
    where, params = _where_domain(domain_id, active_only)
    params["limit"] = int(limit)
    sql = text(f"""
        SELECT
            a.asset_value AS host,
            a.ip_address AS ip,
            c.cve_id,
            c.severity,
            c.cvss,
            c.description,
            a.risk_score
        FROM asset_cves c
        JOIN assets a ON a.id = c.asset_id
        WHERE {where}
        ORDER BY c.cvss DESC NULLS LAST, a.asset_value
        LIMIT :limit
    """)
    return pd.read_sql(sql, engine, params=params)


def service_fingerprints(domain_id=None, active_only=True):
    """Distinct (product, version) pairs seen across the scoped domain."""
    where, params = _where_domain(domain_id, active_only)
    sql = text(f"""
        SELECT
            s.product,
            s.version,
            COUNT(DISTINCT a.id) AS host_count,
            COUNT(*) AS occurrences
        FROM services s
        JOIN assets a ON a.id = s.asset_id
        WHERE {where}
          AND s.product IS NOT NULL
          AND s.product <> ''
        GROUP BY s.product, s.version
        ORDER BY host_count DESC, s.product
    """)
    return pd.read_sql(sql, engine, params=params)