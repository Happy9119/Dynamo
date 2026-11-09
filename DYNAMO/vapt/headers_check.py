import os

VAPT_HEADERS_ENABLED = os.environ.get(
    "VAPT_HEADERS_ENABLED", "false"
).strip().lower() in ("1", "true", "yes", "on")

REQUIRED_HEADERS = {
    "strict-transport-security": (
        "high", "hsts_missing",
        "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'",
    ),
    "content-security-policy": (
        "medium", "csp_missing",
        "Define a Content-Security-Policy to limit XSS impact",
    ),
    "x-frame-options": (
        "medium", "x_frame_options_missing",
        "Add 'X-Frame-Options: DENY' or use CSP frame-ancestors",
    ),
    "x-content-type-options": (
        "low", "x_content_type_options_missing",
        "Add 'X-Content-Type-Options: nosniff'",
    ),
    "referrer-policy": (
        "low", "referrer_policy_missing",
        "Add 'Referrer-Policy: strict-origin-when-cross-origin'",
    ),
    "permissions-policy": (
        "info", "permissions_policy_missing",
        "Add a Permissions-Policy header to limit feature access",
    ),
}


async def check_url(session, url):
    if not VAPT_HEADERS_ENABLED:
        return []
    findings = []
    try:
        async with session.get(url, allow_redirects=False) as r:
            headers_lower = {k.lower(): v for k, v in r.headers.items()}
            is_https = url.lower().startswith("https://")

            for hdr, (sev, vtype, fix) in REQUIRED_HEADERS.items():
                if hdr == "strict-transport-security" and not is_https:
                    continue
                if hdr not in headers_lower:
                    findings.append({
                        "vuln_type": vtype,
                        "severity": sev,
                        "url": url,
                        "parameter": None,
                        "evidence": f"Header '{hdr}' not present in response",
                        "remediation": fix,
                    })

            for cookie_hdr in r.headers.getall("Set-Cookie", []):
                parts = [p.strip() for p in cookie_hdr.split(";")]
                name = parts[0].split("=", 1)[0].strip() if parts else "?"
                flags = {p.lower() for p in parts[1:]}

                has_httponly = "httponly" in flags
                has_secure = "secure" in flags
                has_samesite = any(f.startswith("samesite") for f in flags)

                if not has_httponly:
                    findings.append({
                        "vuln_type": "cookie_missing_httponly",
                        "severity": "medium",
                        "url": url,
                        "parameter": None,
                        "evidence": f"Cookie '{name}' missing HttpOnly",
                        "remediation": "Set HttpOnly on session cookies",
                    })
                if is_https and not has_secure:
                    findings.append({
                        "vuln_type": "cookie_missing_secure",
                        "severity": "medium",
                        "url": url,
                        "parameter": None,
                        "evidence": f"Cookie '{name}' missing Secure on HTTPS",
                        "remediation": "Set Secure flag on HTTPS cookies",
                    })
                if not has_samesite:
                    findings.append({
                        "vuln_type": "cookie_missing_samesite",
                        "severity": "low",
                        "url": url,
                        "parameter": None,
                        "evidence": f"Cookie '{name}' missing SameSite",
                        "remediation": "Set SameSite=Lax or SameSite=Strict",
                    })
                    
            for hdr, vtype in {
                "server":              "info_server_banner",
                "x-powered-by":        "info_x_powered_by",
                "x-aspnet-version":    "info_aspnet_version",
                "x-aspnetmvc-version": "info_aspnetmvc_version",
                "x-generator":         "info_generator",
            }.items():
                val = headers_lower.get(hdr)
                if val:
                    findings.append({
                        "vuln_type": vtype,
                        "severity": "info",
                        "url": url,
                        "parameter": None,
                        "evidence": f"{hdr}: {val}",
                        "remediation": f"Remove the {hdr} header",
                    })      
    except Exception:
        pass
    return findings