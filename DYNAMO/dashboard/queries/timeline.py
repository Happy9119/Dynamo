import json
import pandas as pd
import streamlit as st
from sqlalchemy import text
from storage.database import engine


def _fmt_dt_cols(df, *cols):
    for c in cols:
        if c in df.columns:
            df[c] = pd.to_datetime(df[c], errors="coerce").dt.strftime("%d-%m-%Y %H:%M:%S")
    return df


# ────────────────────────────────────────────────────────────────────────────
# GLOBAL EVENTS
# ────────────────────────────────────────────────────────────────────────────

def get_change_events(domain_id=None, event_types=None, limit=500):

    clauses = ["1=1"]
    params = {"limit": int(limit)}

    if domain_id is not None:
        clauses.append("a.domain_id = :domain_id")
        params["domain_id"] = int(domain_id)

    if event_types:
        placeholders = ", ".join([f":et{i}" for i in range(len(event_types))])
        for i, t in enumerate(event_types):
            params[f"et{i}"] = t
        clauses.append(f"c.event_type IN ({placeholders})")

    where = " AND ".join(clauses)

    df = pd.read_sql(text(f"""
        SELECT
            c.created_at AS "When",
            a.asset_value AS "Asset",
            c.event_type  AS "Event",
            c.old_value   AS "Old",
            c.new_value   AS "New"
        FROM change_events c
        JOIN assets a ON a.id = c.asset_id
        WHERE {where}
        ORDER BY c.created_at DESC
        LIMIT :limit
    """), engine, params=params)
    return _fmt_dt_cols(df, "When")


@st.cache_data(ttl=300, show_spinner=False)
def get_event_types():
    df = pd.read_sql(
        text("SELECT DISTINCT event_type FROM change_events ORDER BY event_type"),
        engine,
    )
    return df["event_type"].tolist()


def get_event_counts(domain_id=None):
    """Count per event_type, scoped to a domain."""
    params = {}
    dom_clause = ""
    if domain_id is not None:
        dom_clause = "WHERE a.domain_id = :domain_id"
        params["domain_id"] = int(domain_id)

    return pd.read_sql(text(f"""
        SELECT c.event_type AS "Event", COUNT(*) AS "Count"
        FROM change_events c
        JOIN assets a ON a.id = c.asset_id
        {dom_clause}
        GROUP BY c.event_type
        ORDER BY COUNT(*) DESC
    """), engine, params=params)


# ────────────────────────────────────────────────────────────────────────────
# SCAN DIFF
# ────────────────────────────────────────────────────────────────────────────

def get_scans_for_domain(domain_id=None):
    if domain_id is None:
        df = pd.read_sql(text("""
            SELECT s.id, s.target, s.started_at, s.completed_at, s.status
            FROM scans s
            ORDER BY s.started_at DESC
        """), engine)
        return _fmt_dt_cols(df, "started_at", "completed_at")

    df = pd.read_sql(text("""
        SELECT s.id, s.target, s.started_at, s.completed_at, s.status
        FROM scans s
        WHERE EXISTS (
            SELECT 1
            FROM scan_assets sa
            JOIN assets a ON a.id = sa.asset_id
            WHERE sa.scan_id = s.id
              AND a.domain_id = :domain_id
        )
        ORDER BY s.started_at DESC
    """), engine, params={"domain_id": int(domain_id)})
    return _fmt_dt_cols(df, "started_at", "completed_at")


def get_scan_observations(scan_id):
    return pd.read_sql(text("""
        SELECT
            ao.asset_id,
            a.asset_value AS host,
            ao.ip_address,
            ao.technologies,
            ao.services_json,
            ao.cves_json,
            ao.vapt_json,
            ao.nuclei_json,
            ao.sqli_json,
            ao.risk_score,
            ao.ai_analysis_json
        FROM asset_observations ao
        JOIN assets a ON a.id = ao.asset_id
        WHERE ao.scan_id = :scan_id
    """), engine, params={"scan_id": int(scan_id)})


def _parse_services(raw):
    if raw is None:
        return []
    if isinstance(raw, list):
        return raw
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, list) else []
    except (TypeError, json.JSONDecodeError):
        return []


def _parse_cves(raw):
    if raw is None:
        return []
    if isinstance(raw, list):
        return raw
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, list) else []
    except (TypeError, json.JSONDecodeError):
        return []


# FIX #6 (consumer side): return True only when the observation column was
# actually measured for this scan. Legacy/quick-scan rows write NULL (or the
# string "[]") to signal "we didn't re-run this tool this scan". Without this
# guard, a quick scan makes every VAPT/nuclei/sqli finding look "removed".
def _column_measured(df, col):
    if df is None or df.empty or col not in df.columns:
        return False
    for v in df[col]:
        if v is None:
            continue
        if isinstance(v, str) and v.strip() in ("", "[]", "null", "None"):
            continue
        return True
    return False


def diff_observations(obs_a, obs_b):

    a_hosts = {r["host"]: r["ip_address"] for _, r in obs_a.iterrows()} if not obs_a.empty else {}
    b_hosts = {r["host"]: r["ip_address"] for _, r in obs_b.iterrows()} if not obs_b.empty else {}

    # ── Hosts ────────────────────────────────────────────────────────────
    added_hosts   = sorted((h, b_hosts[h]) for h in (set(b_hosts) - set(a_hosts)))
    removed_hosts = sorted((h, a_hosts[h]) for h in (set(a_hosts) - set(b_hosts)))

    # ── Services (keyed by host + port/proto) ────────────────────────────
    def _service_index(df):
        idx = {}
        for _, r in df.iterrows():
            host = r["host"]
            for svc in _parse_services(r["services_json"]):
                port = svc.get("port")
                proto = (svc.get("protocol") or "tcp").lower()
                key = (host, port, proto)
                idx[key] = (
                    svc.get("service_name") or "?",
                    svc.get("product") or "",
                    svc.get("version") or "",
                )
        return idx

    a_svcs = _service_index(obs_a)
    b_svcs = _service_index(obs_b)

    added_services = []
    for k in sorted(set(b_svcs) - set(a_svcs)):
        host, port, proto = k
        name, prod, ver = b_svcs[k]
        added_services.append((host, f"{port}/{proto}", f"{name}|{prod}|{ver}".rstrip("|")))

    removed_services = []
    for k in sorted(set(a_svcs) - set(b_svcs)):
        host, port, proto = k
        name, prod, ver = a_svcs[k]
        removed_services.append((host, f"{port}/{proto}", f"{name}|{prod}|{ver}".rstrip("|")))

    fingerprint_changes = []
    for k in sorted(set(a_svcs) & set(b_svcs)):
        if a_svcs[k] != b_svcs[k]:
            host, port, proto = k
            fingerprint_changes.append({
                "Host":    host,
                "Service": f"{port}/{proto}",
                "Old":     "|".join(a_svcs[k]).rstrip("|"),
                "New":     "|".join(b_svcs[k]).rstrip("|"),
            })

    # ── CVEs ─────────────────────────────────────────────────────────────
    def _cve_index(df):
        idx = {}
        for _, r in df.iterrows():
            host = r["host"]
            for cve in _parse_cves(r["cves_json"]):
                cid = cve.get("cve")
                if cid:
                    idx[(host, cid)] = cve.get("severity") or "unknown"
        return idx

    a_cves = _cve_index(obs_a)
    b_cves = _cve_index(obs_b)

    added_cves = [(h, c, b_cves[(h, c)]) for (h, c) in sorted(set(b_cves) - set(a_cves))]
    removed_cves = [(h, c, a_cves[(h, c)]) for (h, c) in sorted(set(a_cves) - set(b_cves))]

    ip_changes = []
    for h in set(a_hosts) & set(b_hosts):
        if a_hosts[h] != b_hosts[h]:
            ip_changes.append({"Host": h, "Old IP": a_hosts[h], "New IP": b_hosts[h]})


    # ── VAPT Findings ────────────────────────────────────────────────────
    def _vapt_index(df):
        idx = {}
        for _, r in df.iterrows():
            host = r["host"]
            for v in _parse_cves(r.get("vapt_json")):
                key = (host, v.get("vuln_type"), v.get("url"))
                idx[key] = v.get("severity") or "unknown"
        return idx

    a_vapt_measured = _column_measured(obs_a, "vapt_json")
    b_vapt_measured = _column_measured(obs_b, "vapt_json")
    if a_vapt_measured and b_vapt_measured:
        a_vapt = _vapt_index(obs_a)
        b_vapt = _vapt_index(obs_b)
        added_vapt = [{"Host": h, "Type": t, "URL": u, "Severity": s}
                      for (h, t, u), s in b_vapt.items() if (h, t, u) not in a_vapt]
        removed_vapt = [{"Host": h, "Type": t, "URL": u, "Severity": s}
                        for (h, t, u), s in a_vapt.items() if (h, t, u) not in b_vapt]
    else:
        added_vapt, removed_vapt = [], []

    # ── Nuclei Findings ──────────────────────────────────────────────────
    def _nuclei_index(df):
        idx = {}
        for _, r in df.iterrows():
            host = r["host"]
            for n in _parse_cves(r.get("nuclei_json")):
                key = (host, n.get("template_id"), n.get("matched_at"))
                idx[key] = n.get("severity") or "unknown"
        return idx

    a_nuclei_measured = _column_measured(obs_a, "nuclei_json")
    b_nuclei_measured = _column_measured(obs_b, "nuclei_json")
    if a_nuclei_measured and b_nuclei_measured:
        a_nuclei = _nuclei_index(obs_a)
        b_nuclei = _nuclei_index(obs_b)
        added_nuclei = [{"Host": h, "Template": t, "URL": u, "Severity": s}
                        for (h, t, u), s in b_nuclei.items() if (h, t, u) not in a_nuclei]
        removed_nuclei = [{"Host": h, "Template": t, "URL": u, "Severity": s}
                          for (h, t, u), s in a_nuclei.items() if (h, t, u) not in b_nuclei]
    else:
        added_nuclei, removed_nuclei = [], []

    # ── SQLi Findings ────────────────────────────────────────────────────
    def _sqli_index(df):
        idx = {}
        for _, r in df.iterrows():
            host = r["host"]
            for s in _parse_cves(r.get("sqli_json")):
                key = (host, s.get("url"))
                idx[key] = s.get("technique") or "unknown"
        return idx

    a_sqli_measured = _column_measured(obs_a, "sqli_json")
    b_sqli_measured = _column_measured(obs_b, "sqli_json")
    if a_sqli_measured and b_sqli_measured:
        a_sqli = _sqli_index(obs_a)
        b_sqli = _sqli_index(obs_b)
        added_sqli = [{"Host": h, "URL": u, "Technique": t}
                      for (h, u), t in b_sqli.items() if (h, u) not in a_sqli]
        removed_sqli = [{"Host": h, "URL": u, "Technique": t}
                        for (h, u), t in a_sqli.items() if (h, u) not in b_sqli]
    else:
        added_sqli, removed_sqli = [], []

    def _ai_index(df):
        idx = {}
        for _, r in df.iterrows():
            raw = r.get("ai_analysis_json")
            if not raw:
                continue
            try:
                parsed = json.loads(raw) if isinstance(raw, str) else raw
                idx[r["host"]] = {
                    "score": parsed.get("exploitability_score"),
                    "tier": parsed.get("exploitability_tier"),
                }
            except (json.JSONDecodeError, AttributeError):
                continue
        return idx

    a_ai = _ai_index(obs_a)
    b_ai = _ai_index(obs_b)

    ai_changes = []
    for host in sorted(set(b_ai) - set(a_ai)):
        ai_changes.append({
            "Host": host,
            "Change": "new AI analysis",
            "Detail": f"score={b_ai[host]['score']} tier={b_ai[host]['tier']}",
        })
    for host in sorted(set(a_ai) & set(b_ai)):
        if a_ai[host] != b_ai[host]:
            ai_changes.append({
                "Host": host,
                "Change": "AI re-assessed",
                "Detail": (
                    f"score {a_ai[host]['score']}→{b_ai[host]['score']}, "
                    f"tier {a_ai[host]['tier']}→{b_ai[host]['tier']}"
                ),
            })

    return {
        "added_hosts":         added_hosts,
        "removed_hosts":       removed_hosts,
        "added_services":      added_services,
        "removed_services":    removed_services,
        "fingerprint_changes": fingerprint_changes,
        "added_cves":          added_cves,
        "removed_cves":        removed_cves,
        "ip_changes":          ip_changes,
        "ai_changes":          ai_changes,
        "added_vapt":          added_vapt,
        "removed_vapt":        removed_vapt,
        "added_nuclei":        added_nuclei,
        "removed_nuclei":      removed_nuclei,
        "added_sqli":          added_sqli,
        "removed_sqli":        removed_sqli,
    }