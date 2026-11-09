from core.tech_utils import parse_tech_string

RISKY_TECH_KEYWORDS = {
    "php": 10, "apache": 10, "iis": 10, "asp.net": 10,
    "nginx": 5, "wordpress": 15, "jenkins": 20, "tomcat": 15,
    "drupal": 15, "joomla": 15, "jquery": 5,
    "flask": 5, "django": 5, "express": 5, "node.js": 5,
    "rails": 5, "gunicorn": 5, "werkzeug": 5,
}

RISKY_SERVICES = {
    "ftp": 15, "telnet": 25, "smb": 25, "microsoft-ds": 25,
    "ms-wbt-server": 25, "mysql": 20, "postgresql": 20,
    "redis": 20, "mongodb": 20, "elasticsearch": 20,
    "vnc": 25, "ssh": 10,
    "php-fpm": 10, "werkzeug": 10, "gunicorn": 10,
}

RISKY_PORTS = {
    21: ("FTP exposed", 15),
    23: ("Telnet exposed", 25),
    445: ("SMB exposed", 25),
    3389: ("RDP exposed", 25),
    3306: ("MySQL exposed", 20),
    5432: ("PostgreSQL exposed", 20),
    6379: ("Redis exposed", 20),
    27017: ("MongoDB exposed", 20),
    9200: ("Elasticsearch exposed", 20),
    5900: ("VNC exposed", 25),
}

CVE_SEVERITY_POINTS = {
    "critical": 40, "high": 25, "medium": 10, "low": 5,
}

NUCLEI_SEVERITY_POINTS = {
    "critical": 40, "high": 25, "medium": 10, "low": 3, "info": 0,
}

VAPT_SEVERITY_POINTS = {
    "critical": 30,
    "high": 15,
    "medium": 8,
    "low": 3,
    "info": 0,
}

STANDARD_SERVICE_PORTS = {
    "ftp": {20, 21},
    "ssh": {22},
    "telnet": {23},
    "smtp": {25, 587, 465},
    "domain": {53},
    "http": {80},
    "https": {443},
    "pop3": {110, 995},
    "imap": {143, 993},
    "microsoft-ds": {445},
    "smb": {445},
    "ms-wbt-server": {3389},
    "rdp": {3389},
    "mysql": {3306},
    "postgresql": {5432},
    "redis": {6379},
    "mongodb": {27017},
    "elasticsearch": {9200},
    "vnc": {5900},
}

def calculate_risk(asset):
    score = 0
    findings = []
    seen = set()

    def add(finding_text, points):
        nonlocal score
        if finding_text in seen:
            return
        seen.add(finding_text)
        findings.append(finding_text)
        score += points

    # Technology risk
    for tech in asset.technologies:
        name, _ = parse_tech_string(tech)
        name_lower = name.lower()
        for keyword, points in RISKY_TECH_KEYWORDS.items():
            if keyword in name_lower:
                add(f"{name} detected", points)

    # Ports / services
    for svc in asset.services:
        if svc.port in RISKY_PORTS:
            label, points = RISKY_PORTS[svc.port]
            add(f"{label} (port {svc.port})", points)
        elif svc.service_name:
            svc_lower = svc.service_name.lower()
            if svc_lower in RISKY_SERVICES:
                points = RISKY_SERVICES[svc_lower]
                standard = STANDARD_SERVICE_PORTS.get(svc_lower, set())
                if svc.port in standard:
                    add(f"{svc.service_name.upper()} exposed on port {svc.port}", points)
                else:
                    add(f"{svc.service_name.upper()} exposed on non-standard port {svc.port}", points)

    # CVEs
    for cve in asset.cves:
        sev = (cve.get("severity") or "").lower()
        pts = CVE_SEVERITY_POINTS.get(sev)
        if pts:
            add(f"{sev.capitalize()} CVE: {cve.get('cve', 'unknown')}", pts)

    # Nuclei
    for finding in getattr(asset, "nuclei_findings", []) or []:
        sev = (getattr(finding, "severity", None) or "").lower()
        pts = NUCLEI_SEVERITY_POINTS.get(sev, 0)
        if pts:
            tid = getattr(finding, "template_id", "unknown")
            name = getattr(finding, "name", "") or ""
            add(f"Nuclei [{sev.upper()}] {tid} — {name}", pts)

    # SQLi
    for sqli in getattr(asset, "sqli_findings", []) or []:
        if getattr(sqli, "vulnerable", False):
            add(f"SQLi confirmed: {sqli.url}", 45)

    for v in getattr(asset, "vulns", []) or []:
        sev = (getattr(v, "severity", None) or "").lower()
        pts = VAPT_SEVERITY_POINTS.get(sev, 0)
        if pts:
            vt = getattr(v, "vuln_type", "unknown")
            url = getattr(v, "url", "")
            add(f"VAPT [{sev.upper()}] {vt}: {url}", pts)

    # Parameter / content surface
    params = getattr(asset, "parameter_urls", []) or []
    if len(params) >= 20:
        add(f"Large parameter surface ({len(params)} URLs with query params)", 5)
    elif len(params) >= 5:
        add(f"Parameter surface exposed ({len(params)} URLs)", 2)

    paths = getattr(asset, "discovered_paths", []) or []
    if len(paths) >= 25:
        add(f"Large content discovery surface ({len(paths)} paths)", 5)

    score = min(score, 100)
    summary = ", ".join(findings) if findings else "No significant risk indicators"
    return score, summary