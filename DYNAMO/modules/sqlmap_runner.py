import asyncio
import hashlib
import os
import re
import shutil

from config.tools import SQLMAP_BIN, SQLMAP_LEVEL, SQLMAP_RISK, SQLMAP_TIMEOUT
from modules._subprocess_utils import communicate_with_timeout

VULN_RE = re.compile(
    r"is vulnerable|sql injection|parameter .* is vulnerable", re.I
)
TYPE_RE = re.compile(r"^\s*Type:\s*(.+)$", re.MULTILINE)
PAYLOAD_RE = re.compile(r"^\s*Payload:\s*(.+)$", re.MULTILINE)


def _extract_findings(url, text):
    findings = []
    current_type = None
    current_payload = None

    def flush():
        nonlocal current_type, current_payload
        if current_type or current_payload:
            findings.append({
                "url": url,
                "vulnerable": True,
                "technique": current_type,
                "payload": current_payload,
            })
        current_type = None
        current_payload = None

    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("Parameter:"):
            flush()
        elif stripped.lower().startswith("type:"):
            current_type = stripped.split(":", 1)[1].strip()
        elif stripped.lower().startswith("payload:"):
            current_payload = stripped.split(":", 1)[1].strip()

    flush()
    return findings


async def run_sqlmap(url, output_root="sqlmap_data"):
    if not (shutil.which(SQLMAP_BIN) or shutil.which(SQLMAP_BIN.split("/")[-1])):
        return [{"url": url, "vulnerable": False, "skipped": True}]

    url_hash = hashlib.sha256(url.encode()).hexdigest()
    outdir = os.path.join(output_root, url_hash)
    os.makedirs(outdir, exist_ok=True)

    proc = await asyncio.create_subprocess_exec(
        SQLMAP_BIN,
        "-u", url,
        "--batch",
        "--random-agent",
        f"--level={SQLMAP_LEVEL}",
        f"--risk={SQLMAP_RISK}",
        "--tamper=space2comment",
        "--flush-session",
        f"--output-dir={outdir}",
        "-v", "0",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        start_new_session=True,
    )
    try:
        stdout, _ = await communicate_with_timeout(proc, SQLMAP_TIMEOUT)
    except TimeoutError as e:
        raise RuntimeError(f"sqlmap timeout on {url}: {e}") from e

    text = stdout.decode(errors="replace")

    if VULN_RE.search(text):
        findings = _extract_findings(url, text)
        if findings:
            return findings
        return [{
            "url": url,
            "vulnerable": True,
            "technique": "unknown (raw match)",
            "payload": "detected by sqlmap",
        }]

    return [{"url": url, "vulnerable": False}]