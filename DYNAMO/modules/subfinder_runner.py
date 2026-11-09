import asyncio
import shutil
from core.validators import is_valid_hostname
from config.tools import SUBFINDER_BIN, SUBFINDER_TIMEOUT
from modules._subprocess_utils import communicate_with_timeout


async def run_subfinder(domain, progress=None):
    def _log(msg):
        if progress:
            progress(msg)
        else:
            print(msg)

    if not shutil.which(SUBFINDER_BIN) and not shutil.which(SUBFINDER_BIN.split("/")[-1]):
        _log(f"[!] subfinder not found ({SUBFINDER_BIN}) — skipping")
        return []

    try:
        process = await asyncio.create_subprocess_exec(
            SUBFINDER_BIN, "-d", domain, "-silent",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
        try:
            stdout, stderr = await communicate_with_timeout(
                process, SUBFINDER_TIMEOUT)
        except TimeoutError as e:
            raise RuntimeError(f"subfinder timeout: {e}") from e
    except FileNotFoundError as e:
        raise RuntimeError(f"Could not execute subfinder at '{SUBFINDER_BIN}'") from e

    if process.returncode != 0:
        err = stderr.decode(errors="replace").strip()
        raise RuntimeError(f"subfinder exit {process.returncode}: {err}")

    results = []
    for line in stdout.decode(errors="replace").splitlines():
        cleaned = line.strip()
        if not cleaned:
            continue
        if is_valid_hostname(cleaned):
            results.append(cleaned)
    return sorted(set(results))