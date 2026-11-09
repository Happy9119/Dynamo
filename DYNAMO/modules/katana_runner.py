import asyncio
import os
import shutil
import tempfile

from config.tools import KATANA_BIN, KATANA_TIMEOUT
from modules._subprocess_utils import communicate_with_timeout

async def run_katana(hosts: list[str], scope_domain: str, progress=None) -> list[str]:
    def _log(msg):
        if progress:
            progress(msg)
        else:
            print(msg)

    if not hosts:
        return []
    if not (shutil.which(KATANA_BIN) or shutil.which(KATANA_BIN.split("/")[-1])):
        _log("[!] katana not installed — skipping crawl")
        return []

    fd, tmp = tempfile.mkstemp()
    try:
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(hosts))

        proc = await asyncio.create_subprocess_exec(
            KATANA_BIN,
            "-list", tmp,
            "-ef", "png,css,jpeg,pdf",  
            "-cs", scope_domain,
            "-aff",
            "-silent",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
        try:
            stdout, stderr = await communicate_with_timeout(proc, KATANA_TIMEOUT)
        except TimeoutError as e:
            raise RuntimeError(f"katana timeout: {e}") from e
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)

    if proc.returncode != 0:
        err = stderr.decode(errors="replace").strip()[:300]
        raise RuntimeError(f"katana exit {proc.returncode}: {err}")

    return sorted({l.strip() for l in stdout.decode(errors="replace").splitlines() if l.strip()})