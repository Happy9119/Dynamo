import asyncio
import shutil

from config.tools import GAU_BIN, GAU_TIMEOUT
from modules._subprocess_utils import communicate_with_timeout


async def run_gau(domain: str, progress=None) -> list[str]:
    def _log(msg):
        if progress:
            progress(msg)
        else:
            print(msg)

    if not (shutil.which(GAU_BIN) or shutil.which(GAU_BIN.split("/")[-1])):
        _log("[!] gau not installed — skipping")
        return []

    try:
        proc = await asyncio.create_subprocess_exec(
            GAU_BIN, domain, "--threads", "10",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
        try:
            stdout, stderr = await communicate_with_timeout(proc, GAU_TIMEOUT)
        except TimeoutError as e:
            raise RuntimeError(f"gau timeout: {e}") from e
    except FileNotFoundError:
        return []

    if proc.returncode != 0:
        err = stderr.decode(errors="replace").strip()[:300]
        raise RuntimeError(f"gau exit {proc.returncode}: {err}")

    urls = set()
    for line in stdout.decode(errors="replace").splitlines():
        line = line.strip()
        if line.startswith("http"):
            urls.add(line)
    return sorted(urls)