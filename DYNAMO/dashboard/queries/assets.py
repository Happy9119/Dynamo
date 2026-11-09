import pandas as pd
from sqlalchemy import text
from storage.database import engine


def _fmt_dt_cols(df, *cols):
    for c in cols:
        if c in df.columns:
            df[c] = pd.to_datetime(df[c], errors="coerce").dt.strftime("%d-%m-%Y %H:%M:%S")
    return df


def _asset_filter_clauses(domain_id=None, risk_min=0, active_only=True,
                          search=""):
    clauses = ["1=1"]
    params = {}

    if domain_id is not None:
        clauses.append("a.domain_id = :domain_id")
        params["domain_id"] = int(domain_id)

    if active_only:
        clauses.append("a.is_active = TRUE")

    if risk_min and risk_min > 0:
        clauses.append("a.risk_score >= :risk_min")
        params["risk_min"] = int(risk_min)

    if search:
        clauses.append(
            "(LOWER(a.asset_value) LIKE :q OR "
            " LOWER(COALESCE(a.title,'')) LIKE :q OR "
            " LOWER(COALESCE(a.technologies,'')) LIKE :q)"
        )
        params["q"] = f"%{search.lower()}%"

    return " AND ".join(clauses), params


def list_assets(domain_id=None, risk_min=0, active_only=True,
                search="", limit=2000):
    where, params = _asset_filter_clauses(
        domain_id=domain_id, risk_min=risk_min,
        active_only=active_only, search=search,
    )
    params["limit"] = int(limit)

    sql = text(f"""
        SELECT
            a.id,
            a.asset_value        AS host,
            a.ip_address         AS ip,
            a.url,
            a.status_code,
            a.title,
            a.technologies,
            a.risk_score,
            a.risk_summary,
            a.ai_analysis_json,
            a.first_seen,
            a.last_seen,
            a.is_active,
            d.apex
        FROM assets a
        LEFT JOIN domains d ON d.id = a.domain_id
        WHERE {where}
        ORDER BY a.risk_score DESC, a.asset_value
        LIMIT :limit
    """)
    df = pd.read_sql(sql, engine, params=params)
    return _fmt_dt_cols(df, "first_seen", "last_seen")


def count_assets(domain_id=None, active_only=True, risk_min=0):
    where, params = _asset_filter_clauses(
        domain_id=domain_id, risk_min=risk_min,
        active_only=active_only, search="",
    )
    sql = text(f"SELECT COUNT(*) AS c FROM assets a WHERE {where}")
    df = pd.read_sql(sql, engine, params=params)
    return int(df.iloc[0]["c"]) if not df.empty else 0


def count_critical(domain_id=None, active_only=True):
    where, params = _asset_filter_clauses(
        domain_id=domain_id, risk_min=80,
        active_only=active_only, search="",
    )
    sql = text(f"SELECT COUNT(*) AS c FROM assets a WHERE {where}")
    df = pd.read_sql(sql, engine, params=params)
    return int(df.iloc[0]["c"]) if not df.empty else 0


def risk_distribution(domain_id=None, active_only=True):
    """Return a DataFrame with columns: severity, count (always 4 rows)."""
    where, params = _asset_filter_clauses(
        domain_id=domain_id, active_only=active_only, search="",
    )
    sql = text(f"""
        SELECT
            CASE
                WHEN a.risk_score >= 80 THEN 'Critical'
                WHEN a.risk_score >= 50 THEN 'High'
                WHEN a.risk_score >= 20 THEN 'Medium'
                ELSE 'Low'
            END AS severity,
            COUNT(*) AS count
        FROM assets a
        WHERE {where}
        GROUP BY 1
    """)
    got = pd.read_sql(sql, engine, params=params)

    order = ["Critical", "High", "Medium", "Low"]
    got = got.set_index("severity").reindex(order, fill_value=0).reset_index()
    return got


def top_technologies(domain_id=None, active_only=True, limit=15):
    from core.tech_utils import parse_tech_string

    where, params = _asset_filter_clauses(
        domain_id=domain_id, active_only=active_only, search="",
    )
    sql = text(f"""
        SELECT a.technologies
        FROM assets a
        WHERE {where} AND a.technologies IS NOT NULL AND a.technologies <> ''
    """)
    df = pd.read_sql(sql, engine, params=params)

    counts = {}
    for cell in df["technologies"]:
        for raw in str(cell).split(","):
            raw = raw.strip()
            if not raw:
                continue
            name, _ = parse_tech_string(raw)
            if name:
                counts[name] = counts.get(name, 0) + 1

    if not counts:
        return pd.DataFrame(columns=["Technology", "Count"])

    out = (pd.DataFrame(
        [{"Technology": k, "Count": v} for k, v in counts.items()]
    ).sort_values("Count", ascending=False).head(limit).reset_index(drop=True))
    return out


def get_asset_detail(asset_id: int):
    sql = text("""
        SELECT a.*, d.apex
        FROM assets a
        LEFT JOIN domains d ON d.id = a.domain_id
        WHERE a.id = :asset_id
    """)
    df = pd.read_sql(sql, engine, params={"asset_id": int(asset_id)})
    return df.iloc[0].to_dict() if not df.empty else None

def top_risky_assets(domain_id=None, limit=5):
    where, params = _asset_filter_clauses(domain_id=domain_id, active_only=True)
    params["limit"] = int(limit)
    sql = text(f"""
        SELECT a.id, a.asset_value AS host, a.risk_score, a.risk_summary,
               d.apex
        FROM assets a
        LEFT JOIN domains d ON d.id = a.domain_id
        WHERE {where} AND a.risk_score > 0
        ORDER BY a.risk_score DESC, a.asset_value
        LIMIT :limit
    """)
    return pd.read_sql(sql, engine, params=params)


def findings_grouped_by_asset(domain_id=None, severities=None,
                              sources=None, text_filter="", limit=2000):
    from queries.findings import list_all_findings
    df = list_all_findings(
        domain_id=domain_id, severities=severities,
        sources=sources, limit=limit,
    )
    if df.empty:
        return df
    if text_filter:
        needle = text_filter.lower()
        mask = (
            df["title"].str.lower().str.contains(needle, na=False)
            | df["host"].str.lower().str.contains(needle, na=False)
            | df["url"].fillna("").str.lower().str.contains(needle, na=False)
        )
        df = df[mask]
    return df