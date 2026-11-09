import re
from urllib.parse import urlparse, parse_qs, urlunparse, urlencode

_PASSWD_LINE = re.compile(
    r"^([a-zA-Z_][a-zA-Z0-9_-]*):[x*!]?:\d+:\d+:[^:]*:[^:]*:[^:\n]+$",
    re.MULTILINE,
)

_KNOWN_USERS = {
    "root", "daemon", "bin", "sys", "sync", "games", "man", "lp",
    "mail", "news", "uucp", "proxy", "www-data", "backup", "list",
    "irc", "gnats", "nobody", "systemd-network", "systemd-resolve",
    "messagebus", "sshd", "chrony", "mysql", "postgres", "redis",
    "nginx", "apache",
}

def _is_passwd_leak(body: str) -> bool:
    if not body:
        return False
    usernames = _PASSWD_LINE.findall(body)
    if not usernames:
        return False
    return any(u in _KNOWN_USERS for u in usernames)

def _is_ssrf_metadata(body: str, resp) -> bool:
    if not body:
        return False
    
    ctype = (resp.headers.get("Content-Type") or "").lower()
    if "text/html" in ctype:
        return False

    if "ami-id" in body or "instance-id" in body or "security-credentials" in body:
        return True
        
    if "project-id" in body or "service-accounts" in body:
        return True
        
    if "vmId" in body or "subscriptionId" in body:
        return True

    return False

def _is_open_redirect(body: str, resp) -> bool:
    if resp.status not in (301, 302, 303, 307, 308):
        return False
        
    loc = resp.headers.get("Location") or ""
    if not loc:
        return False

    parsed = urlparse(loc)
    
    if not parsed.netloc and loc.startswith("//"):
        parsed = urlparse("https:" + loc)

    return parsed.netloc == "dynamo-redirect.example.com"


PROBES = {
    "xss_reflection": {
        "payload": "<dynamo_xss_probe>",
        "severity": "medium",
        "detect": lambda body, resp: (
            "text/html" in (resp.headers.get("Content-Type") or "").lower()
            and "<dynamo_xss_probe>" in body
        ),
        "remediation": "Encode user input on output; deploy a strict CSP",
    },
    "sqli_error": {
        "payload": "'",
        "severity": "high",
        "detect": lambda body, resp: any(s in body.lower() for s in [
            "you have an error in your sql syntax",
            "unclosed quotation mark after the character string",
            "pg_query()",
            "pg_exec()",
            "warning: mysql",
            "microsoft ole db provider for sql server",
            "ora-0",
            "quoted string not properly terminated",
            "syntax error at or near",
        ]),
        "remediation": "Use parameterized queries; suppress DB error output",
    },
    "lfi": {
        "payload": "../../../../../../etc/passwd",
        "severity": "critical",
        "detect": lambda body, resp: _is_passwd_leak(body),
        "remediation": "Never build file paths from user input",
    },
    "open_redirect": {
        "payload": "https://dynamo-redirect.example.com",
        "severity": "medium",
        "detect": lambda body, resp: _is_open_redirect(body, resp),
        "remediation": "Allow-list redirect destinations",
    },
    "ssrf_metadata": {
        "payload": "http://169.254.169.254/latest/meta-data/",
        "severity": "critical",
        "detect": lambda body, resp: _is_ssrf_metadata(body, resp),
        "remediation": "Block link-local and RFC1918 addresses on server-side fetches",
    },
}

async def probe_url(session, url, timeout=8):
    findings = []
    parsed = urlparse(url)
    if not parsed.query:
        return findings

    params = parse_qs(parsed.query, keep_blank_values=True)

    for name in params:
        for pname, probe in PROBES.items():
            new_params = dict(params)
            new_params[name] = [probe["payload"]]
            new_query = urlencode(new_params, doseq=True)
            target = urlunparse(parsed._replace(query=new_query))

            try:
                async with session.get(
                    target, allow_redirects=False, timeout=timeout,
                ) as r:
                    body = await r.text(errors="replace")
                    if len(body) > 200000:
                        body = body[:200000]
                    if probe["detect"](body, r):
                        findings.append({
                            "vuln_type": pname,
                            "severity": probe["severity"],
                            "url": url,
                            "parameter": name,
                            "evidence": f"Payload triggered detection on '{name}'",
                            "remediation": probe["remediation"],
                        })
            except Exception:
                continue
    return findings