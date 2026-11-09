import streamlit as st
import pandas as pd
from sqlalchemy import text
from storage.database import engine

def _fmt_dt_cols(df, *cols):
    for c in cols:
        if c in df.columns:
            df[c] = pd.to_datetime(df[c], errors="coerce").dt.strftime("%d-%m-%Y %H:%M:%S")
    return df

def list_all_findings(domain_id=None, severities=None, sources=None,
                      limit=500):
    params = {"limit": int(limit)}

    where_domain = ""
    if domain_id is not None:
        where_domain = "AND a.domain_id = :domain_id"
        params["domain_id"] = int(domain_id)

    outer_where = ""
    if severities:
        placeholders = ", ".join(f":sev{i}" for i in range(len(severities)))
        for i, s in enumerate(severities):
            params[f"sev{i}"] = s.lower()
        outer_where = f"WHERE LOWER(severity) IN ({placeholders})"

    subqueries = []
    srcs = sources or ["vapt", "sqli", "nuclei", "cve", "ffuf"]

    if "vapt" in srcs:
        subqueries.append(f"""
            SELECT
                COALESCE(v.severity, 'info') AS severity,
                'vapt' AS source,
                a.asset_value AS host,
                d.apex AS domain,
                v.vuln_type AS title,
                v.url AS url,
                v.evidence AS evidence,
                v.remediation AS remediation,
                a.id AS asset_id,
                v.detected_at AS detected_at,
                '' AS confidence
            FROM asset_vulns v
            JOIN assets a ON a.id = v.asset_id
            LEFT JOIN domains d ON d.id = a.domain_id
            WHERE a.is_active = TRUE {where_domain}
        """)

    if "sqli" in srcs:
        subqueries.append(f"""
            SELECT
                CASE 
                    WHEN LOWER(COALESCE(s.technique, '')) LIKE '%time%' OR LOWER(COALESCE(s.technique, '')) LIKE '%union%' THEN 'critical'
                    ELSE 'high'
                END AS severity,
                'sqli' AS source,
                a.asset_value AS host,
                d.apex AS domain,
                'SQL Injection' AS title,
                s.url AS url,
                CONCAT('Technique: ', COALESCE(s.technique, 'unknown')) AS evidence,
                'Use parameterized queries; suppress DB error output' AS remediation,
                a.id AS asset_id,
                s.created_at AS detected_at,
                '' AS confidence
            FROM sqli_findings s
            JOIN assets a ON a.id = s.asset_id
            LEFT JOIN domains d ON d.id = a.domain_id
            WHERE a.is_active = TRUE {where_domain}
        """)

    if "nuclei" in srcs:
        subqueries.append(f"""
            SELECT
                COALESCE(n.severity, 'info') AS severity,
                'nuclei' AS source,
                a.asset_value AS host,
                d.apex AS domain,
                CONCAT(n.template_id, ': ', COALESCE(n.name, '')) AS title,
                n.matched_at AS url,
                COALESCE(n.description, '') AS evidence,
                '' AS remediation,
                a.id AS asset_id,
                n.created_at AS detected_at,
                '' AS confidence
            FROM nuclei_findings n
            JOIN assets a ON a.id = n.asset_id
            LEFT JOIN domains d ON d.id = a.domain_id
            WHERE a.is_active = TRUE {where_domain}
        """)

    if "cve" in srcs:
        subqueries.append(f"""
            SELECT
                COALESCE(c.severity, 'info') AS severity,
                'cve' AS source,
                a.asset_value AS host,
                d.apex AS domain,
                c.cve_id AS title,
                '' AS url,
                COALESCE(c.description, '') AS evidence,
                '' AS remediation,
                a.id AS asset_id,
                c.created_at AS detected_at,
                COALESCE(c.match_confidence, 'low') AS confidence
            FROM asset_cves c
            JOIN assets a ON a.id = c.asset_id
            LEFT JOIN domains d ON d.id = a.domain_id
            WHERE a.is_active = TRUE {where_domain}
        """)

    if "ffuf" in srcs:
        subqueries.append(f"""
            SELECT
                'info' AS severity,
                'ffuf' AS source,
                a.asset_value AS host,
                d.apex AS domain,
                'Discovered Path' AS title,
                u.url AS url,
                '' AS evidence,
                '' AS remediation,
                a.id AS asset_id,
                CAST(NULL AS TIMESTAMP) AS detected_at,
                '' AS confidence
            FROM asset_urls u
            JOIN assets a ON a.id = u.asset_id
            LEFT JOIN domains d ON d.id = a.domain_id
            WHERE a.is_active = TRUE AND u.source = 'ffuf' {where_domain}
        """)

    if not subqueries:
        return pd.DataFrame(columns=[
            "severity", "source", "host", "domain", "title",
            "url", "evidence", "remediation", "asset_id", "detected_at", "confidence",
        ])

    union_sql = " UNION ALL ".join(subqueries)
    sql = text(f"""
        SELECT * FROM ({union_sql}) AS all_findings
        {outer_where}
        ORDER BY
            CASE LOWER(severity)
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
                ELSE 5
            END,
            detected_at DESC NULLS LAST
        LIMIT :limit
    """)
    df = pd.read_sql(sql, engine, params=params)
    return _fmt_dt_cols(df, "detected_at")

def findings_summary(domain_id=None):
    df = list_all_findings(domain_id=domain_id, limit=100000)
    if df.empty:
        return {"critical": 0, "high": 0, "medium": 0,
                "low": 0, "info": 0, "total": 0}
    counts = df["severity"].str.lower().value_counts().to_dict()
    for k in ("critical", "high", "medium", "low", "info"):
        counts.setdefault(k, 0)
    counts["total"] = int(sum(counts[k] for k in
                             ("critical", "high", "medium", "low", "info")))
    return counts

@st.cache_data(ttl=15, show_spinner=False)
def findings_summary_all():
    """Fetches all findings once and groups by domain to prevent N+1 queries."""
    df = list_all_findings(limit=1000000)
    if df.empty:
        return pd.DataFrame()
    
    counts = df.groupby("domain")["severity"].value_counts().unstack(fill_value=0).reset_index()
    for c in ["critical", "high", "medium", "low", "info"]:
        if c not in counts.columns:
            counts[c] = 0
            
    counts["total"] = counts[["critical", "high", "medium", "low", "info"]].sum(axis=1)
    return counts