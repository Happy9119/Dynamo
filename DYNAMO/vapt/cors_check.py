async def check_url(session, url):
    findings = []
    origin = "https://dynamo-probe.example.com"
    try:
        async with session.get(url, allow_redirects=False,
                               headers={"Origin": origin}) as r:
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = (r.headers.get("Access-Control-Allow-Credentials") or "").lower()

            if acao == "*" and acac == "true":
                findings.append({
                    "vuln_type": "cors_wildcard_with_credentials",
                    "severity": "high",
                    "url": url,
                    "parameter": None,
                    "evidence": "ACAO=* with ACAC=true",
                    "remediation": "Do not combine wildcard origin with credentials",
                })
            elif acao == origin:
                findings.append({
                    "vuln_type": "cors_origin_reflected",
                    "severity": "medium" if acac == "true" else "low",
                    "url": url,
                    "parameter": None,
                    "evidence": f"Origin '{origin}' reflected in ACAO",
                    "remediation": "Allow-list trusted origins instead of reflecting",
                })
            elif acao == "*":
                findings.append({
                    "vuln_type": "cors_wildcard",
                    "severity": "low",
                    "url": url,
                    "parameter": None,
                    "evidence": "ACAO=*",
                    "remediation": "Restrict ACAO to trusted origins if sensitive data",
                })
    except Exception:
        pass
    return findings