from io import BytesIO
from datetime import datetime
import re as _re
import pandas as pd
from xml.sax.saxutils import escape
from urllib.parse import urlparse, urlunparse

from sqlalchemy import text
from storage.database import engine

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak,
    HRFlowable,
)
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.legends import Legend

from queries.domains import get_domains
from queries.assets import list_assets
from queries.services import list_cves
from queries.findings import list_all_findings, findings_summary


# ────────────────────────────────────────────────────────────────────────
# Palette
# ────────────────────────────────────────────────────────────────────────
PURPLE       = colors.HexColor("#7C3AED")
PURPLE_DARK  = colors.HexColor("#4C1D95")
PURPLE_LIGHT = colors.HexColor("#F5F3FF")
BORDER       = colors.HexColor("#E9D5FF")
TEXT         = colors.HexColor("#1F2937")
MUTED        = colors.HexColor("#6B7280")

SEV_COLORS = {
    "critical": colors.HexColor("#991B1B"),
    "high":     colors.HexColor("#DC2626"),
    "medium":   colors.HexColor("#EA580C"),
    "low":      colors.HexColor("#CA8A04"),
    "info":     colors.HexColor("#2563EB"),
    "total":    PURPLE_DARK,
}

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SRC_RANK = {"VAPT": 0, "VAPT (JS)": 1, "Nuclei": 2, "SQLI": 3, "FFUF": 4}

_IP_RE = _re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _is_ip(s):
    return bool(s and _IP_RE.match(str(s).strip()))


# ────────────────────────────────────────────────────────────────────────
# Styles
# ────────────────────────────────────────────────────────────────────────
def _styles():
    return {
        "title": ParagraphStyle("title", fontName="Helvetica-Bold",
                                fontSize=24, leading=28,
                                textColor=PURPLE_DARK, spaceAfter=2),
        "subtitle": ParagraphStyle("subtitle", fontName="Helvetica",
                                   fontSize=12, leading=16,
                                   textColor=PURPLE, spaceAfter=12),
        "section": ParagraphStyle("section", fontName="Helvetica-Bold",
                                  fontSize=14, leading=18,
                                  textColor=PURPLE_DARK,
                                  spaceBefore=16, spaceAfter=8),
        "subsection": ParagraphStyle("subsection", fontName="Helvetica-Bold",
                                     fontSize=11, leading=14,
                                     textColor=PURPLE_DARK,
                                     spaceBefore=8, spaceAfter=4),
        "body": ParagraphStyle("body", fontName="Helvetica",
                               fontSize=9, leading=12, textColor=TEXT),
        "note": ParagraphStyle("note", fontName="Helvetica-Oblique",
                               fontSize=8, leading=11, textColor=MUTED),
        "footer": ParagraphStyle("footer", fontName="Helvetica",
                                 fontSize=8, leading=11,
                                 textColor=MUTED, alignment=1),
        "kpi_val": ParagraphStyle("kpi_val", fontName="Helvetica-Bold",
                                  fontSize=20, leading=24,
                                  textColor=TEXT, alignment=1),
        "kpi_lbl": ParagraphStyle("kpi_lbl", fontName="Helvetica-Bold",
                                  fontSize=8, leading=10,
                                  textColor=MUTED, alignment=1),
        "th": ParagraphStyle("th", fontName="Helvetica-Bold",
                             fontSize=9, textColor=colors.white),
    }


# ────────────────────────────────────────────────────────────────────────
# Cell helpers
# ────────────────────────────────────────────────────────────────────────
def _cell_text(c):
    if c is None:
        return "—"
    try:
        if pd.isna(c):
            return "—"
    except (TypeError, ValueError):
        pass
    if isinstance(c, str):
        s = c.strip()
    elif isinstance(c, (list, tuple)):
        s = " ".join(str(x) for x in c)
    elif hasattr(c, "tolist"):
        try:
            v = c.tolist()
            s = " ".join(str(x) for x in v) if isinstance(v, list) else str(v)
        except Exception:
            s = str(c)
    else:
        s = str(c)
    if not s or s.lower() in ("none", "nan", "nat", "na", "<na>", "null"):
        return "—"
    return s


def _severity_para(sev, styles):
    sev_str = str(sev).lower()
    color = SEV_COLORS.get(sev_str, TEXT)
    style = ParagraphStyle(
        "sev", parent=styles["body"], textColor=colors.white,
        backColor=color, fontSize=8, borderPadding=2, alignment=1,
    )
    return Paragraph(f"<b>{escape(str(sev).upper())}</b>", style)


def _build_table(rows, headers, col_widths, styles, sev_col=None,
                 url_cols=None):
    """Table with per-column wrapping. url_cols: set of col indices that
    use CJK wrapping (breaks at any char, ideal for URLs/hosts)."""
    header_row = [Paragraph(escape(str(h)), styles["th"]) for h in headers]
    data = [header_row]

    cell_style = ParagraphStyle(
        "tcell_body", parent=styles["body"],
        splitLongWords=1, wordWrap="LTR",
    )
    url_style = ParagraphStyle(
        "tcell_url", parent=cell_style, wordWrap="CJK",
    )
    url_cols = set(url_cols or ())

    for r in rows:
        row_data = []
        for i, c in enumerate(r):
            txt = _cell_text(c)
            if sev_col is not None and i == sev_col:
                row_data.append(_severity_para(txt, styles))
            else:
                st = url_style if i in url_cols else cell_style
                row_data.append(Paragraph(escape(txt), st))
        data.append(row_data)

    t = Table(data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), PURPLE),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.5, BORDER),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PURPLE_LIGHT]),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return t


def _paginated_table(story, rows, headers, col_widths, styles,
                     sev_col=None, url_cols=None, chunk_size=20):
    total = len(rows)
    if total == 0:
        return
    for start in range(0, total, chunk_size):
        chunk = rows[start:start + chunk_size]
        if start > 0:
            story.append(PageBreak())
        story.append(_build_table(
            chunk, headers, col_widths, styles,
            sev_col=sev_col, url_cols=url_cols,
        ))


# ────────────────────────────────────────────────────────────────────────
# URL / parameter helpers
# ────────────────────────────────────────────────────────────────────────
def _strip_query(url):
    """scheme://netloc + path — drops query & fragment. Safe on junk input."""
    if not url:
        return "—"
    try:
        p = urlparse(url)
        if not p.scheme and not p.netloc:
            return url
        return urlunparse((p.scheme, p.netloc, p.path, "", "", "")) or url
    except Exception:
        return url


def _extract_first_query_key(url):
    if not url:
        return "—"
    try:
        q = urlparse(url).query
        if not q:
            return "—"
        first = q.split("&", 1)[0]
        k = first.split("=", 1)[0]
        return k or "—"
    except Exception:
        return "—"


def _nuclei_name(template_id, name):
    tid = (str(template_id) if template_id is not None else "").strip()
    nm = (str(name) if name is not None else "").strip()
    if tid and nm and tid.lower() != "none" and nm.lower() != "none":
        return f"{tid}: {nm}"
    if tid and tid.lower() != "none":
        return tid
    if nm and nm.lower() != "none":
        return nm
    return "Unknown"


# ────────────────────────────────────────────────────────────────────────
# Pie chart
# ────────────────────────────────────────────────────────────────────────
def _make_pie_chart(assets):
    drawing = Drawing(400, 200)
    pie = Pie()
    pie.x = 100
    pie.y = 25
    pie.width = 150
    pie.height = 150
    pie.data = []
    pie.labels = []
    pie.slices.strokeWidth = 1
    pie.slices.strokeColor = colors.white

    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    if not assets.empty:
        for score in assets["risk_score"]:
            if score >= 80:     counts["Critical"] += 1
            elif score >= 50:   counts["High"] += 1
            elif score >= 20:   counts["Medium"] += 1
            else:               counts["Low"] += 1

    colors_map = [
        ("Critical", SEV_COLORS["critical"]),
        ("High",     SEV_COLORS["high"]),
        ("Medium",   SEV_COLORS["medium"]),
        ("Low",      SEV_COLORS["low"]),
    ]

    idx = 0
    for label, color in colors_map:
        val = counts[label]
        if val > 0:
            pie.data.append(val)
            pie.labels.append(f"{label}: {val}")
            pie.slices[idx].fillColor = color
            idx += 1

    if not pie.data:
        return None

    legend = Legend()
    legend.x = 280
    legend.y = 100
    legend.alignment = 'right'
    legend.fontName = 'Helvetica'
    legend.fontSize = 9
    legend.colorNamePairs = [(c, l) for (l, c) in colors_map if counts[l] > 0]

    drawing.add(pie)
    drawing.add(legend)
    return drawing


# ────────────────────────────────────────────────────────────────────────
# Shared lookups
# ────────────────────────────────────────────────────────────────────────
def _resolve_apex(domain_id):
    dom_df = get_domains()
    row = dom_df[dom_df["domain_id"] == domain_id]
    if row.empty:
        raise ValueError(f"Domain id {domain_id} not found")
    return row.iloc[0]["apex"]


# ────────────────────────────────────────────────────────────────────────
# Assets — single combined table (host + type + IP)
# ────────────────────────────────────────────────────────────────────────
def _asset_rows(domain_id, apex):
    sql = text("""
        SELECT DISTINCT a.asset_value AS host, i.ip_address AS ip
        FROM assets a
        LEFT JOIN asset_ips i
            ON i.asset_id = a.id AND i.is_active = TRUE
        WHERE a.domain_id = :did AND a.is_active = TRUE
    """)
    df = pd.read_sql(sql, engine, params={"did": int(domain_id)})
    if df.empty:
        return []

    def _type_rank(host):
        if host == apex:      return 0
        if _is_ip(host):      return 2
        return 1

    def _type_label(host):
        if host == apex:      return "Apex"
        if _is_ip(host):      return "IP"
        return "Subdomain"

    df["_rank"] = df["host"].apply(_type_rank)
    df = (df.sort_values(["_rank", "host", "ip"],
                         na_position="last")
            .reset_index(drop=True))

    rows = []
    for i, (_, r) in enumerate(df.iterrows(), start=1):
        h = r["host"] or "—"
        ip = r["ip"] if pd.notna(r["ip"]) else "—"
        rows.append([str(i), h, _type_label(h), ip])
    return rows


# ────────────────────────────────────────────────────────────────────────
# Unified findings (non-CVE: VAPT, VAPT-JS, Nuclei, SQLI, FFUF)
# ────────────────────────────────────────────────────────────────────────
def _unified_findings_df(domain_id):
    sql = text("""
        SELECT severity, template_id, name, evidence_url, parameter,
               host, source
        FROM (
            SELECT
                v.severity AS severity,
                NULL AS template_id,
                v.vuln_type AS name,
                v.url AS evidence_url,
                v.parameter AS parameter,
                a.asset_value AS host,
                CASE WHEN v.vuln_type LIKE 'js_secret%'
                     THEN 'VAPT (JS)' ELSE 'VAPT' END AS source
            FROM asset_vulns v
            JOIN assets a ON a.id = v.asset_id
            WHERE a.domain_id = :did AND a.is_active = TRUE

            UNION ALL

            SELECT
                COALESCE(n.severity, 'info') AS severity,
                n.template_id AS template_id,
                n.name AS name,
                n.matched_at AS evidence_url,
                NULL AS parameter,
                a.asset_value AS host,
                'Nuclei' AS source
            FROM nuclei_findings n
            JOIN assets a ON a.id = n.asset_id
            WHERE a.domain_id = :did AND a.is_active = TRUE

            UNION ALL

            SELECT
                CASE WHEN LOWER(COALESCE(s.technique, '')) LIKE '%time%'
                       OR LOWER(COALESCE(s.technique, '')) LIKE '%union%'
                     THEN 'critical' ELSE 'high' END AS severity,
                NULL AS template_id,
                'SQL Injection' AS name,
                s.url AS evidence_url,
                NULL AS parameter,
                a.asset_value AS host,
                'SQLI' AS source
            FROM sqli_findings s
            JOIN assets a ON a.id = s.asset_id
            WHERE a.domain_id = :did AND a.is_active = TRUE

            UNION ALL

            SELECT
                'info' AS severity,
                NULL AS template_id,
                'Discovered Path' AS name,
                u.url AS evidence_url,
                NULL AS parameter,
                a.asset_value AS host,
                'FFUF' AS source
            FROM asset_urls u
            JOIN assets a ON a.id = u.asset_id
            WHERE a.domain_id = :did AND a.is_active = TRUE
              AND u.source = 'ffuf'
        ) u
    """)
    df = pd.read_sql(sql, engine, params={"did": int(domain_id)})
    if df.empty:
        return df

    df["severity"]     = df["severity"].fillna("info").astype(str).str.lower()
    df["name"]         = df["name"].fillna("—").astype(str)
    df["evidence_url"] = df["evidence_url"].fillna("").astype(str)
    df["host"]         = df["host"].fillna("—").astype(str)
    df["source"]       = df["source"].fillna("—").astype(str)

    def _display_name(row):
        if row["source"] == "Nuclei":
            return _nuclei_name(row["template_id"], row["name"])
        return row["name"] or "—"
    df["display_name"] = df.apply(_display_name, axis=1)

    def _param(row):
        p = row["parameter"]
        if p is not None and str(p).strip() and str(p).lower() != "nan":
            return str(p)
        if row["source"] == "SQLI":
            return _extract_first_query_key(row["evidence_url"])
        return "—"
    df["parameter"] = df.apply(_param, axis=1)

    df["_srank"]   = df["severity"].map(_SEV_RANK).fillna(99)
    df["_srcrank"] = df["source"].map(_SRC_RANK).fillna(99)
    df = (df.sort_values(["_srank", "_srcrank", "host", "display_name"])
            .drop(columns=["_srank", "_srcrank", "template_id", "name"])
            .reset_index(drop=True))
    return df


# ────────────────────────────────────────────────────────────────────────
# Cover (shared by both report types) — EXACT same layout as today
# ────────────────────────────────────────────────────────────────────────
def _build_cover(story, styles, apex, total_assets, active_assets,
                 n_findings, n_critical, assets):
    story.append(Spacer(1, 2 * cm))
    story.append(Paragraph("DYNAMO Security Report", styles["title"]))
    story.append(Paragraph(f"Target: <b>{escape(apex)}</b>", styles["subtitle"]))
    story.append(Paragraph(
        f"Generated: {datetime.now().strftime('%d-%m-%Y %H:%M:%S')}",
        styles["note"],
    ))
    story.append(Spacer(1, 1 * cm))

    kpi_data = [
        [Paragraph(str(total_assets),  styles["kpi_val"]),
         Paragraph(str(active_assets), styles["kpi_val"]),
         Paragraph(str(n_findings),    styles["kpi_val"]),
         Paragraph(str(n_critical),    styles["kpi_val"])],
        [Paragraph("TOTAL ASSETS",   styles["kpi_lbl"]),
         Paragraph("ACTIVE ASSETS",  styles["kpi_lbl"]),
         Paragraph("TOTAL FINDINGS", styles["kpi_lbl"]),
         Paragraph("CRITICAL FINDINGS", styles["kpi_lbl"])],
    ]
    kpi_table = Table(kpi_data, colWidths=[4 * cm] * 4)
    kpi_table.setStyle(TableStyle([
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("BOX", (0, 0), (0, -1), 1, BORDER),
        ("BOX", (1, 0), (1, -1), 1, BORDER),
        ("BOX", (2, 0), (2, -1), 1, BORDER),
        ("BOX", (3, 0), (3, -1), 1, BORDER),
        ("BACKGROUND", (0, 0), (-1, -1), PURPLE_LIGHT),
        ("TOPPADDING", (0, 0), (-1, 0), 12),
        ("BOTTOMPADDING", (0, 1), (-1, 1), 12),
    ]))
    story.append(kpi_table)
    story.append(Spacer(1, 1.5 * cm))

    chart = _make_pie_chart(assets)
    if chart:
        story.append(Paragraph("Asset Risk Distribution", styles["section"]))
        story.append(chart)


def _build_footer(story, styles):
    story.append(Spacer(1, 1 * cm))
    story.append(HRFlowable(width="100%", thickness=0.4,
                            color=BORDER, spaceAfter=8))
    story.append(Paragraph(
        "Generated by DYNAMO. For authorized security testing only.",
        styles["footer"],
    ))


# ────────────────────────────────────────────────────────────────────────
# EXEC report — unchanged behaviour
# ────────────────────────────────────────────────────────────────────────
def _build_exec_report(domain_id):
    styles = _styles()
    apex = _resolve_apex(domain_id)

    assets   = list_assets(domain_id=domain_id, active_only=False)
    findings = list_all_findings(domain_id=domain_id, limit=200)

    total_assets  = len(assets)
    active_assets = int(assets["is_active"].sum()) if not assets.empty else 0
    n_findings    = len(findings)
    n_critical    = (len(findings[findings["severity"] == "critical"])
                     if not findings.empty else 0)

    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=1.5 * cm, rightMargin=1.5 * cm,
        topMargin=1.5 * cm, bottomMargin=1.5 * cm,
        title=f"DYNAMO Recon Report — {apex}",
    )
    story = []
    _build_cover(story, styles, apex, total_assets, active_assets,
                 n_findings, n_critical, assets)

    story.append(Spacer(1, 1 * cm))
    story.append(Paragraph("Top Critical Findings", styles["section"]))
    story.append(HRFlowable(width="100%", thickness=0.6,
                            color=BORDER, spaceAfter=6))
    crit = (findings[findings["severity"].str.lower() == "critical"].head(10)
            if not findings.empty else pd.DataFrame())
    if not crit.empty:
        v_rows = crit[["severity", "source", "host", "title"]].values.tolist()
        story.append(_build_table(
            v_rows, ["Severity", "Source", "Host", "Finding"],
            [2 * cm, 2 * cm, 4 * cm, 8 * cm], styles, sev_col=0,
        ))
    else:
        story.append(Paragraph("No critical findings identified.",
                               styles["body"]))

    doc.build(story)
    pdf = buf.getvalue()
    buf.close()
    return pdf, f"dynamo_exec_{apex.replace('.', '_')}_{datetime.now():%d-%m-%Y}.pdf"


# ────────────────────────────────────────────────────────────────────────
# TECH report — 4 content sections + cover
# ────────────────────────────────────────────────────────────────────────
def _build_tech_report(domain_id):
    styles = _styles()
    apex = _resolve_apex(domain_id)

    assets_all      = list_assets(domain_id=domain_id, active_only=False)
    cves            = list_cves(domain_id=domain_id, active_only=True)
    findings_counts = findings_summary(domain_id=domain_id)
    unified         = _unified_findings_df(domain_id)
    asset_rows      = _asset_rows(domain_id, apex)

    total_assets  = len(assets_all)
    active_assets = (int(assets_all["is_active"].sum())
                     if not assets_all.empty else 0)
    n_findings    = int(findings_counts.get("total", 0))
    n_critical    = int(findings_counts.get("critical", 0))

    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=1.5 * cm, rightMargin=1.5 * cm,
        topMargin=1.5 * cm, bottomMargin=1.5 * cm,
        title=f"DYNAMO Recon Report — {apex}",
    )
    story = []

    # ── A) Cover ─────────────────────────────────────────────────────
    _build_cover(story, styles, apex, total_assets, active_assets,
                 n_findings, n_critical, assets_all)

    # ── B) Findings by Severity ──────────────────────────────────────
    story.append(PageBreak())
    story.append(Paragraph("Findings by Severity", styles["section"]))
    story.append(HRFlowable(width="100%", thickness=0.6,
                            color=BORDER, spaceAfter=6))

    sev_rows = []
    for i, (key, label) in enumerate(
        [("critical", "Critical"),
         ("high",     "High"),
         ("medium",   "Medium"),
         ("low",      "Low"),
         ("info",     "Info")], start=1,
    ):
        sev_rows.append([
            str(i), label, str(int(findings_counts.get(key, 0))),
        ])
    sev_rows.append([
        "—", "Total", str(int(findings_counts.get("total", 0))),
    ])

    story.append(_build_table(
        sev_rows,
        ["#", "Severity", "Count"],
        [1.5 * cm, 5.0 * cm, 3.5 * cm],
        styles, sev_col=1,
    ))

    # ── C) Assets ────────────────────────────────────────────────────
    story.append(PageBreak())
    story.append(Paragraph(f"Assets ({len(asset_rows)})", styles["section"]))
    story.append(HRFlowable(width="100%", thickness=0.6,
                            color=BORDER, spaceAfter=6))

    if not asset_rows:
        story.append(Paragraph("No active assets recorded.", styles["body"]))
    else:
        story.append(_build_table(
            asset_rows,
            ["#", "Asset", "Type", "IP Address"],
            [0.7 * cm, 7.0 * cm, 2.5 * cm, 6.8 * cm],
            styles, url_cols={1, 3},
        ))

    # ── D) Findings ──────────────────────────────────────────────────
    story.append(PageBreak())
    story.append(Paragraph(f"Findings ({len(unified)})", styles["section"]))
    story.append(HRFlowable(width="100%", thickness=0.6,
                            color=BORDER, spaceAfter=6))

    if unified.empty:
        story.append(Paragraph("No findings recorded.", styles["body"]))
    else:
        rows = []
        for i, (_, r) in enumerate(unified.iterrows(), start=1):
            rows.append([
                str(i),
                r["severity"],
                r["display_name"],
                r["parameter"],
                r["host"],
                r["evidence_url"],
                r["source"],
            ])
        _paginated_table(
            story, rows,
            ["#", "Severity", "Vuln Name", "Param",
             "Host", "Evidence URL", "Source"],
            [0.7 * cm, 1.5 * cm, 3.5 * cm, 1.5 * cm,
             3.0 * cm, 5.0 * cm, 1.8 * cm],
            styles, sev_col=1, url_cols={4, 5}, chunk_size=20,
        )

    # ── E) CVEs ──────────────────────────────────────────────────────
    story.append(PageBreak())
    story.append(Paragraph(
        f"CVE Findings ({len(cves)})", styles["section"],
    ))
    story.append(HRFlowable(width="100%", thickness=0.6,
                            color=BORDER, spaceAfter=6))

    if cves.empty:
        story.append(Paragraph("No CVEs matched.", styles["body"]))
    else:
        cve_sorted = cves.copy()
        cve_sorted["_rank"] = (cve_sorted["severity"].astype(str).str.lower()
                               .map(_SEV_RANK).fillna(99))
        cve_sorted = cve_sorted.sort_values(
            ["_rank", "cvss"], ascending=[True, False],
        )
        rows = []
        for i, (_, r) in enumerate(cve_sorted.iterrows(), start=1):
            cvss_v = r.get("cvss")
            cvss_str = f"{cvss_v:.1f}" if pd.notna(cvss_v) else "—"
            rows.append([
                str(i),
                r.get("host") or "—",
                r.get("cve_id") or "—",
                r.get("severity") or "—",
                cvss_str,
                r.get("description") or "—",
            ])
        _paginated_table(
            story, rows,
            ["#", "Host", "CVE ID", "Severity", "CVSS", "Description"],
            [0.7 * cm, 3.5 * cm, 2.5 * cm, 1.7 * cm, 1.3 * cm, 7.3 * cm],
            styles, sev_col=3, url_cols={1}, chunk_size=20,
        )

    # ── Footer ───────────────────────────────────────────────────────
    _build_footer(story, styles)

    doc.build(story)
    pdf = buf.getvalue()
    buf.close()
    filename = (
        f"dynamo_report_{apex.replace('.', '_')}_"
        f"{datetime.now():%d-%m-%Y_%H-%M-%S}.pdf"
    )
    return pdf, filename


# ────────────────────────────────────────────────────────────────────────
# Public API — unchanged signature
# ────────────────────────────────────────────────────────────────────────
def generate_domain_report(domain_id, report_type="full"):
    if report_type == "exec":
        return _build_exec_report(domain_id)
    return _build_tech_report(domain_id)