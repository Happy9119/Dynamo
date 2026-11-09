from schemas.asset import Asset

def build_asset_analysis_prompt(asset: Asset) -> str:
    technologies = ", ".join(asset.technologies) if asset.technologies else "None detected"

    services_text = "\n".join(
        f"- Port {s.port}/{s.protocol} ({s.service_name} - {s.product or ''} {s.version or ''})".strip()
        for s in asset.services
    ) or "- None recorded"

    cve_text = "\n".join(
        f"- {c.get('cve','?')} ({c.get('severity','?')}, CVSS {c.get('cvss','?')})"
        for c in asset.cves
    ) or "- None matched"

    nuclei_text = "\n".join(
        f"- [{(f.severity or 'info').upper()}] "
        f"{f.template_id or '?'}: {f.name or ''} @ {f.matched_at or ''}"
        for f in (asset.nuclei_findings or [])
    ) or "- None"

    sqli_text = "\n".join(
        f"- {s.url} (technique={s.technique or '?'}, payload={s.payload or '?'})"
        for s in (asset.sqli_findings or []) if s.vulnerable
    ) or "- None"

    vulns_text = "\n".join(
        f"- [{(v.severity or 'info').upper()}] {v.vuln_type} @ {v.url}"
        + (f" (param: {v.parameter})" if v.parameter else "")
        for v in (asset.vulns or [])
    ) or "- None"

    param_sample = "\n".join(f"- {u}" for u in (asset.parameter_urls or [])[:5]) or "- None"
    paths_sample = "\n".join(f"- {u}" for u in (asset.discovered_paths or [])[:5]) or "- None"
    js_sample = "\n".join(f"- {u}" for u in (asset.js_endpoints or [])[:5]) or "- None"

    return f"""You are an Offensive Security & EASM Intelligence Engine supporting an AUTHORIZED penetration test.

Analyze the asset below and produce an actionable attack-surface analysis.
Do NOT output generic security advice. Focus on real exploit mechanics.

Target Asset:
- Host: {asset.asset_value}
- Resolved IPs: {", ".join(asset.resolved_ips) or "None"}
- Title: {asset.title or "N/A"}
- Technologies: {technologies}
- Services:
{services_text}
- Matched CVEs:
{cve_text}
- Nuclei findings:
{nuclei_text}
- Confirmed SQLi:
{sqli_text}
- VAPT findings:
{vulns_text}
- Parameter URLs (sample):
{param_sample}
- Discovered paths (sample):
{paths_sample}
- JS-derived endpoints (sample):
{js_sample}
- Initial Risk Score: {asset.risk_score}

CRITICAL OUTPUT RULES:
1. Respond with exactly one JSON object. No markdown fences, no prose before or after.
2. Every string value must be on a single line. Replace any internal newline with the two-character sequence \\n.
3. Escape every double-quote inside a string value as \\". Escape every backslash as \\\\.
4. No trailing commas. No comments. Keep every description under 300 characters.

JSON schema:
{{
  "exploitability_score": <int 0-100>,
  "exploitability_tier": "<Critical|High|Medium|Low>",
  "attack_vector_summary": "<one-line string>",
  "attack_path": [
    {{"step_number": 1, "title": "<one-line>", "description": "<one-line>", "target_component": "<one-line>"}}
  ],
  "suggested_recon_actions": [
    {{"tool_command": "<one-line>", "purpose": "<one-line>"}}
  ],
  "mitigation_priority": ["<one-line>", "<one-line>"]
}}

"""