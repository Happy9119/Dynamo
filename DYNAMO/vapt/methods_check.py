RISKY_METHODS = {
    "TRACE": ("medium", "trace_enabled",
              "Disable TRACE (can facilitate XST)"),
}

async def check_url(session, url):
    findings = []
    try:
        async with session.options(url, allow_redirects=False) as r:
            allow = (r.headers.get("Allow") or r.headers.get("allow") or "").upper()

            for method, (sev, vtype, fix) in RISKY_METHODS.items():
                if method not in allow:
                    continue

                confirmed = False
                try:
                    async with session.request(
                        "TRACE", url, allow_redirects=False, timeout=5,
                    ) as tr:
                        if tr.status == 200:
                            confirmed = True
                except Exception:
                    pass
                if confirmed:
                    findings.append({
                        "vuln_type": vtype,
                        "severity": sev,
                        "url": url,
                        "parameter": None,
                        "evidence": "TRACE confirmed with 200 response",
                        "remediation": fix,
                    })
                
    except Exception:
        pass
    return findings