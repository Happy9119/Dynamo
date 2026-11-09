import asyncio
import json
import os
import shutil
import tempfile

from config.tools import NUCLEI_BIN, NUCLEI_TIMEOUT, NUCLEI_CONCURRENCY
from modules._subprocess_utils import communicate_with_timeout


async def run_nuclei(targets: list[str], severity="critical,high,medium,low", progress=None) -> list[dict]:
    def _log(msg):
        if progress:
            progress(msg)
        else:
            print(msg)

    if not targets:
        return []
    if not (shutil.which(NUCLEI_BIN) or shutil.which(NUCLEI_BIN.split("/")[-1])):
        _log("[!] nuclei not installed — skipping")
        return []

    fd, tmp = tempfile.mkstemp()
    try:
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(targets))

        proc = await asyncio.create_subprocess_exec(
            NUCLEI_BIN,
            "-l", tmp,
            "-jsonl",
            "-silent",
            "-severity", severity,
            "-timeout", "5",
            "-retries", "0",
            "-c", str(NUCLEI_CONCURRENCY),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
        try:
            stdout, stderr = await communicate_with_timeout(proc, NUCLEI_TIMEOUT)
        except TimeoutError as e:
            raise RuntimeError(f"nuclei timeout: {e}") from e
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)

    findings = []
    for line in stdout.decode(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            findings.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    if proc.returncode != 0 and not findings:
        err = stderr.decode(errors="replace").strip()[:300]
        raise RuntimeError(f"nuclei exit {proc.returncode}: {err}")

    if proc.returncode != 0 and findings:
        _log(f"    [!] nuclei exited {proc.returncode} but produced {len(findings)} findings — keeping them")

    return findings