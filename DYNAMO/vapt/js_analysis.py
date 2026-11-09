import re
import aiohttp
import math
from collections import Counter
from core.domain_utils import host_belongs_to_apex, extract_apex
from urllib.parse import urljoin, urlparse

SECRET_PATTERNS = {
    "aws_access_key": (r"AKIA[0-9A-Z]{16}", "critical",
                       "Rotate the AWS key immediately and remove from client bundle"),
    "google_api_key": (r"AIza[0-9A-Za-z_-]{35}", "high",
                       "Restrict the key by referrer and rotate"),
    "github_pat": (r"ghp_[0-9a-zA-Z]{36}", "critical",
                   "Revoke the GitHub PAT"),
    "slack_token": (r"xox[baprs]-[0-9a-zA-Z-]{10,48}", "high",
                    "Revoke the Slack token"),
    "stripe_live_key": (r"sk_live_[0-9a-zA-Z]{24}", "critical",
                        "Rotate the Stripe live key"),
    "private_key": (r"-----BEGIN (RSA|EC|OPENSSH|DSA|PGP) PRIVATE KEY-----",
                    "critical", "Remove private key from client bundle"),
    "firebase_url": (r"https://[a-z0-9-]+\.firebaseio\.com", "info",
                     "Verify Firebase security rules"),
    "aws_s3_url": (r"s3[.-][a-z0-9-]+\.amazonaws\.com", "info",
                   "Verify S3 bucket ACLs"),
}

ENDPOINT_PATTERNS = [
    r'fetch\(\s*[\'"`]([^\'"`]+)[\'"`]',
    r'axios\.(?:get|post|put|delete|patch)\(\s*[\'"`]([^\'"`]+)[\'"`]',
    r'\.open\(\s*[\'"][A-Z]+[\'"]\s*,\s*[\'"`]([^\'"`]+)[\'"`]',
    r'url:\s*[\'"`]([^\'"`]+)[\'"`]',
    r'action:\s*[\'"`]([^\'"`]+)[\'"`]',
]

INTERESTING_PARAM = re.compile(
    r"(?:api[_-]?key|token|secret|password|passwd|pwd|auth)=",
    re.I,
)

MAX_BODY = 2_000_000

STRUCTURAL_SECRET_PATTERNS = {"private_key", "firebase_url", "aws_s3_url"}

TOKEN_PATTERNS = [
    ("bearer_token", re.compile(r"Bearer\s+[A-Za-z0-9._-]{20,}")),
    ("aws_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("github_pat", re.compile(r"ghp_[A-Za-z0-9]{20,}")),
    ("github_pat_v2", re.compile(r"github_pat_[A-Za-z0-9_]{20,}")),
    ("db_url", re.compile(r"(?:mongodb(?:\+srv)?|mysql|postgres(?:ql)?)://[^\"\s]{8,}")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
]

STRUCTURAL_TOKEN_PATTERNS = {"aws_key", "github_pat", "github_pat_v2", "private_key"}

LIBRARY_PATH_MARKERS = (
    "/vendor/", "/libs/", "/plugins/", "/node_modules/",
)

LIBRARY_FILENAME_PREFIXES = [
    "echarts", "quill", "jquery", "bootstrap", "lodash", "moment",
    "react", "vue", "angular", "d3", "highlight", "prism",
    "codemirror", "tinymce", "pdf", "chart",
]

KEYVAL_PATTERNS = [
    re.compile(
        r'["\'](?P<key>api[_-]?key|apikey|access[_-]?token|auth[_-]?token'
        r'|secret[_-]?key|client[_-]?secret|bearer[_-]?token|private[_-]?key)'
        r'["\']?\s*[:=]\s*["\'](?P<val>[^"\']{12,})["\']',
        re.IGNORECASE,
    ),
]


def _is_library_url(url: str) -> bool:
    if not url:
        return False
    try:
        parsed = urlparse(url)
    except Exception:
        return False

    path = (parsed.path or "").lower()
    if not path:
        return False

    for marker in LIBRARY_PATH_MARKERS:
        if marker in path:
            return True

    filename = path.rsplit("/", 1)[-1]
    if not filename:
        return False

    stem = filename.rsplit(".", 1)[0]
    for prefix in LIBRARY_FILENAME_PREFIXES:
        if stem == prefix:
            return True
        if stem.startswith(prefix):
            rest = stem[len(prefix):]
            if rest and rest[0] in (".", "-", "_", "@"):
                return True

    return False


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    freq = Counter(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _passes_entropy_filter(value: str) -> bool:
    L = len(value)
    H = _shannon_entropy(value)
    if L >= 16 and H >= 3.5:
        return True
    if L >= 32 and H >= 3.0:
        return True
    return False


async def analyze_js_url(session, js_url):
    findings = []
    endpoints = []

    if _is_library_url(js_url):
        return findings, endpoints

    try:
        async with session.get(js_url) as r:
            if r.status != 200:
                return findings, endpoints
            ctype = (r.headers.get("Content-Type") or "").lower()
            if "javascript" not in ctype and not js_url.split("?")[0].endswith(".js"):
                return findings, endpoints
            body = await r.text(errors="replace")
    except Exception:
        return findings, endpoints

    if len(body) > MAX_BODY:
        body = body[:MAX_BODY]

    for name, (pattern, severity, remediation) in SECRET_PATTERNS.items():
        for match in re.finditer(pattern, body):
            matched = match.group(0)
            if name not in STRUCTURAL_SECRET_PATTERNS and not _passes_entropy_filter(matched):
                continue
            start = max(0, match.start() - 20)
            end = min(len(body), match.end() + 20)
            snippet = body[start:end].replace("\n", " ")
            findings.append({
                "vuln_type": f"js_secret:{name}",
                "severity": severity,
                "url": js_url,
                "parameter": None,
                "evidence": f"Matched {name}: ...{snippet}...",
                "remediation": remediation,
            })

    for pat in KEYVAL_PATTERNS:
        for m in pat.finditer(body):
            val = m.group("val")
            if not _passes_entropy_filter(val):
                continue
            key = m.group("key")
            findings.append({
                "vuln_type": f"js_secret:generic_{key.lower()}",
                "severity": "high",
                "url": js_url,
                "parameter": None,
                "evidence": f"{key}=…{val[:32]}…",
                "remediation": f"Rotate the leaked {key} and remove from client bundle",
            })

    for name, pat in TOKEN_PATTERNS:
        for m in pat.finditer(body):
            val = m.group(0)
            if name not in STRUCTURAL_TOKEN_PATTERNS and not _passes_entropy_filter(val):
                continue
            findings.append({
                "vuln_type": "js_secret:token",
                "severity": "high",
                "url": js_url,
                "parameter": None,
                "evidence": f"Token-like string: {val[:48]}",
                "remediation": "Rotate leaked credentials; do not ship secrets to clients",
            })

    for pattern in ENDPOINT_PATTERNS:
        for match in re.finditer(pattern, body):
            path = next((g for g in match.groups() if g), None)
            if path and not path.startswith(("data:", "javascript:", "#", "mailto:")):
                endpoints.append(path)

    for m in INTERESTING_PARAM.finditer(body):
        findings.append({
            "vuln_type": "js_param_in_source",
            "severity": "info",
            "url": js_url,
            "parameter": None,
            "evidence": f"Param-like string in JS: {m.group(0)}",
            "remediation": "Audit client-side handling of sensitive parameters",
        })

    return findings, sorted(set(endpoints))


def collect_js_urls(candidate_urls, base_url):
    apex = extract_apex(base_url)
    out = set()
    rejected = 0

    for u in candidate_urls:
        if not isinstance(u, str):
            continue
        bare = u.split("?", 1)[0].lower()
        if not bare.endswith(".js"):
            continue

        absolute = u if u.startswith("http") else urljoin(base_url, u)

        if apex:
            host = (urlparse(absolute).hostname or "").lower()
            if not host_belongs_to_apex(host, apex):
                rejected += 1
                continue

        out.add(absolute)

    if rejected:
        print(f"[!] js_analysis: rejected {rejected} out-of-scope JS URLs")

    return sorted(out)